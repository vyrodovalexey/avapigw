package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// HTTPRoute CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=hr
// +kubebuilder:printcolumn:name="Hostnames",type="string",JSONPath=".spec.hostnames[*]"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// HTTPRoute is the Schema for the httproutes API.
// HTTPRoute provides a way to route HTTP requests.
type HTTPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HTTPRouteSpec   `json:"spec,omitempty"`
	Status HTTPRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HTTPRouteList contains a list of HTTPRoute
type HTTPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HTTPRoute `json:"items"`
}

// HTTPRouteSpec defines the desired state of HTTPRoute
type HTTPRouteSpec struct {
	// ParentRefs references the resources (usually Gateways) that a Route wants
	// to be attached to.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	ParentRefs []ParentRef `json:"parentRefs,omitempty"`

	// Hostnames defines a set of hostnames that should match against the HTTP
	// Host header to select a HTTPRoute used to process the request.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Hostnames []Hostname `json:"hostnames,omitempty"`

	// Rules are a list of HTTP matchers, filters and actions.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Rules []HTTPRouteRule `json:"rules,omitempty"`
}

// HTTPRouteRule defines semantics for matching an HTTP request based on
// conditions (matches), processing it (filters), and forwarding the request
// to an API object (backendRefs).
type HTTPRouteRule struct {
	// Matches define conditions used for matching the rule against incoming
	// HTTP requests. Each match is independent, i.e. this rule will be matched
	// if any one of the matches is satisfied.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Matches []HTTPRouteMatch `json:"matches,omitempty"`

	// Filters define the filters that are applied to requests that match this rule.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Filters []HTTPRouteFilter `json:"filters,omitempty"`

	// BackendRefs defines the backend(s) where matching requests should be sent.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	BackendRefs []HTTPBackendRef `json:"backendRefs,omitempty"`

	// Timeouts defines the timeouts that can be configured for an HTTP request.
	// +optional
	Timeouts *HTTPRouteTimeouts `json:"timeouts,omitempty"`

	// SessionPersistence defines and configures session persistence for the route.
	// +optional
	SessionPersistence *SessionPersistenceConfig `json:"sessionPersistence,omitempty"`

	// Retry defines the retry policy for the route.
	// +optional
	Retry *HTTPRetryPolicy `json:"retry,omitempty"`
}

// HTTPRouteMatch defines the predicate used to match requests to a given action.
type HTTPRouteMatch struct {
	// Path specifies a HTTP request path matcher.
	// +optional
	Path *HTTPPathMatch `json:"path,omitempty"`

	// Headers specifies HTTP request header matchers.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Headers []HTTPHeaderMatch `json:"headers,omitempty"`

	// QueryParams specifies HTTP query parameter matchers.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	QueryParams []HTTPQueryParamMatch `json:"queryParams,omitempty"`

	// Method specifies HTTP method matcher.
	// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;DELETE;CONNECT;OPTIONS;TRACE;PATCH
	// +optional
	Method *HTTPMethod `json:"method,omitempty"`
}

// HTTPPathMatch describes how to select a HTTP route by matching the HTTP request path.
type HTTPPathMatch struct {
	// Type specifies how to match against the path Value.
	// +kubebuilder:validation:Enum=Exact;PathPrefix;RegularExpression
	// +kubebuilder:default=PathPrefix
	// +optional
	Type *PathMatchType `json:"type,omitempty"`

	// Value of the HTTP path to match against.
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:default="/"
	// +optional
	Value *string `json:"value,omitempty"`
}

// PathMatchType specifies the semantics of how HTTP paths should be compared.
// +kubebuilder:validation:Enum=Exact;PathPrefix;RegularExpression
type PathMatchType string

const (
	// PathMatchExact matches the URL path exactly
	PathMatchExact PathMatchType = "Exact"
	// PathMatchPathPrefix matches based on a URL path prefix split by '/'
	PathMatchPathPrefix PathMatchType = "PathPrefix"
	// PathMatchRegularExpression matches based on a regular expression
	PathMatchRegularExpression PathMatchType = "RegularExpression"
)

// HTTPHeaderMatch describes how to select a HTTP route by matching HTTP request headers.
type HTTPHeaderMatch struct {
	// Type specifies how to match against the value of the header.
	// +kubebuilder:validation:Enum=Exact;RegularExpression
	// +kubebuilder:default=Exact
	// +optional
	Type *HeaderMatchType `json:"type,omitempty"`

	// Name is the name of the HTTP Header to be matched.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+$`
	Name string `json:"name"`

	// Value is the value of HTTP Header to be matched.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Value string `json:"value"`
}

// HeaderMatchType specifies the semantics of how HTTP header values should be compared.
// +kubebuilder:validation:Enum=Exact;RegularExpression
type HeaderMatchType string

const (
	// HeaderMatchExact matches the header value exactly
	HeaderMatchExact HeaderMatchType = "Exact"
	// HeaderMatchRegularExpression matches based on a regular expression
	HeaderMatchRegularExpression HeaderMatchType = "RegularExpression"
)

// HTTPQueryParamMatch describes how to select a HTTP route by matching HTTP query parameters.
type HTTPQueryParamMatch struct {
	// Type specifies how to match against the value of the query parameter.
	// +kubebuilder:validation:Enum=Exact;RegularExpression
	// +kubebuilder:default=Exact
	// +optional
	Type *QueryParamMatchType `json:"type,omitempty"`

	// Name is the name of the HTTP query param to be matched.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+$`
	Name string `json:"name"`

	// Value is the value of HTTP query param to be matched.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Value string `json:"value"`
}

// QueryParamMatchType specifies the semantics of how HTTP query parameter values should be compared.
// +kubebuilder:validation:Enum=Exact;RegularExpression
type QueryParamMatchType string

const (
	// QueryParamMatchExact matches the query parameter value exactly
	QueryParamMatchExact QueryParamMatchType = "Exact"
	// QueryParamMatchRegularExpression matches based on a regular expression
	QueryParamMatchRegularExpression QueryParamMatchType = "RegularExpression"
)

// HTTPMethod describes HTTP methods
// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;DELETE;CONNECT;OPTIONS;TRACE;PATCH
type HTTPMethod string

const (
	HTTPMethodGet     HTTPMethod = "GET"
	HTTPMethodHead    HTTPMethod = "HEAD"
	HTTPMethodPost    HTTPMethod = "POST"
	HTTPMethodPut     HTTPMethod = "PUT"
	HTTPMethodDelete  HTTPMethod = "DELETE"
	HTTPMethodConnect HTTPMethod = "CONNECT"
	HTTPMethodOptions HTTPMethod = "OPTIONS"
	HTTPMethodTrace   HTTPMethod = "TRACE"
	HTTPMethodPatch   HTTPMethod = "PATCH"
)

// ============================================================================
// HTTP Route Filters
// ============================================================================

// HTTPRouteFilter defines processing steps that must be completed during the
// request or response lifecycle.
type HTTPRouteFilter struct {
	// Type identifies the type of filter to apply.
	// +kubebuilder:validation:Required
	//nolint:lll // kubebuilder validation enum cannot be shortened
	//+kubebuilder:validation:Enum=RequestHeaderModifier;ResponseHeaderModifier;RequestMirror;RequestRedirect;URLRewrite;DirectResponse;ExtensionRef
	Type HTTPRouteFilterType `json:"type"`

	// RequestHeaderModifier defines a schema for a filter that modifies request headers.
	// +optional
	RequestHeaderModifier *HTTPHeaderFilter `json:"requestHeaderModifier,omitempty"`

	// ResponseHeaderModifier defines a schema for a filter that modifies response headers.
	// +optional
	ResponseHeaderModifier *HTTPHeaderFilter `json:"responseHeaderModifier,omitempty"`

	// RequestMirror defines a schema for a filter that mirrors requests.
	// +optional
	RequestMirror *HTTPRequestMirrorFilter `json:"requestMirror,omitempty"`

	// RequestRedirect defines a schema for a filter that responds to the request
	// with an HTTP redirection.
	// +optional
	RequestRedirect *HTTPRequestRedirectFilter `json:"requestRedirect,omitempty"`

	// URLRewrite defines a schema for a filter that modifies a request during forwarding.
	// +optional
	URLRewrite *HTTPURLRewriteFilter `json:"urlRewrite,omitempty"`

	// DirectResponse defines a schema for a filter that responds directly to the request.
	// +optional
	DirectResponse *HTTPDirectResponseFilter `json:"directResponse,omitempty"`

	// ExtensionRef is an optional, implementation-specific extension to the
	// "filter" behavior.
	// +optional
	ExtensionRef *LocalObjectReference `json:"extensionRef,omitempty"`
}

// HTTPRouteFilterType identifies a type of HTTPRoute filter.
// +kubebuilder:validation:Enum=RequestHeaderModifier;ResponseHeaderModifier;RequestMirror;RequestRedirect;URLRewrite;DirectResponse;ExtensionRef
//
//nolint:lll // kubebuilder validation enum cannot be shortened
type HTTPRouteFilterType string

const (
	// HTTPRouteFilterRequestHeaderModifier modifies request headers
	HTTPRouteFilterRequestHeaderModifier HTTPRouteFilterType = "RequestHeaderModifier"
	// HTTPRouteFilterResponseHeaderModifier modifies response headers
	HTTPRouteFilterResponseHeaderModifier HTTPRouteFilterType = "ResponseHeaderModifier"
	// HTTPRouteFilterRequestMirror mirrors requests to another backend
	HTTPRouteFilterRequestMirror HTTPRouteFilterType = "RequestMirror"
	// HTTPRouteFilterRequestRedirect redirects requests
	HTTPRouteFilterRequestRedirect HTTPRouteFilterType = "RequestRedirect"
	// HTTPRouteFilterURLRewrite rewrites the URL
	HTTPRouteFilterURLRewrite HTTPRouteFilterType = "URLRewrite"
	// HTTPRouteFilterDirectResponse responds directly without forwarding
	HTTPRouteFilterDirectResponse HTTPRouteFilterType = "DirectResponse"
	// HTTPRouteFilterExtensionRef references an extension filter
	HTTPRouteFilterExtensionRef HTTPRouteFilterType = "ExtensionRef"
)

// HTTPRequestMirrorFilter defines configuration for the RequestMirror filter.
type HTTPRequestMirrorFilter struct {
	// BackendRef references a resource where mirrored requests are sent.
	// +kubebuilder:validation:Required
	BackendRef BackendRef `json:"backendRef"`

	// Percent of requests to mirror. Defaults to 100.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=100
	// +optional
	Percent *int32 `json:"percent,omitempty"`
}

// HTTPRequestRedirectFilter defines a filter that redirects a request.
type HTTPRequestRedirectFilter struct {
	// Scheme is the scheme to be used in the value of the Location header in the response.
	// +kubebuilder:validation:Enum=http;https
	// +optional
	Scheme *string `json:"scheme,omitempty"`

	// Hostname is the hostname to be used in the value of the Location header in the response.
	// +optional
	Hostname *PreciseHostname `json:"hostname,omitempty"`

	// Path defines parameters used to modify the path of the incoming request.
	// +optional
	Path *HTTPPathModifier `json:"path,omitempty"`

	// Port is the port to be used in the value of the Location header in the response.
	// +optional
	Port *PortNumber `json:"port,omitempty"`

	// StatusCode is the HTTP status code to be used in response.
	// +kubebuilder:validation:Enum=301;302;303;307;308
	// +kubebuilder:default=302
	// +optional
	StatusCode *int `json:"statusCode,omitempty"`
}

// HTTPURLRewriteFilter defines a filter that modifies a request during forwarding.
type HTTPURLRewriteFilter struct {
	// Hostname is the value to be used to replace the Host header value during forwarding.
	// +optional
	Hostname *PreciseHostname `json:"hostname,omitempty"`

	// Path defines a path rewrite.
	// +optional
	Path *HTTPPathModifier `json:"path,omitempty"`
}

// HTTPPathModifier defines configuration for path modifiers.
type HTTPPathModifier struct {
	// Type defines the type of path modifier.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ReplaceFullPath;ReplacePrefixMatch
	Type HTTPPathModifierType `json:"type"`

	// ReplaceFullPath specifies the value with which to replace the full path of a request.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	ReplaceFullPath *string `json:"replaceFullPath,omitempty"`

	// ReplacePrefixMatch specifies the value with which to replace the prefix match of a request.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	ReplacePrefixMatch *string `json:"replacePrefixMatch,omitempty"`
}

// HTTPPathModifierType defines the type of path modifier.
// +kubebuilder:validation:Enum=ReplaceFullPath;ReplacePrefixMatch
type HTTPPathModifierType string

const (
	// FullPathHTTPPathModifier replaces the full path
	FullPathHTTPPathModifier HTTPPathModifierType = "ReplaceFullPath"
	// PrefixMatchHTTPPathModifier replaces the prefix match
	PrefixMatchHTTPPathModifier HTTPPathModifierType = "ReplacePrefixMatch"
)

// HTTPDirectResponseFilter defines a filter that responds directly to the request.
type HTTPDirectResponseFilter struct {
	// StatusCode is the HTTP status code to be returned.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=599
	StatusCode int `json:"statusCode"`

	// Body is the content of the response body.
	// +optional
	Body *HTTPBody `json:"body,omitempty"`
}

// HTTPBody defines the body of an HTTP response.
type HTTPBody struct {
	// Type defines the type of body content.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Inline;ValueRef
	Type HTTPBodyType `json:"type"`

	// Inline is the inline content of the body.
	// +kubebuilder:validation:MaxLength=4096
	// +optional
	Inline *string `json:"inline,omitempty"`

	// ValueRef references a ConfigMap or Secret containing the body content.
	// +optional
	ValueRef *LocalObjectReference `json:"valueRef,omitempty"`
}

// HTTPBodyType defines the type of HTTP body content.
// +kubebuilder:validation:Enum=Inline;ValueRef
type HTTPBodyType string

const (
	// HTTPBodyTypeInline indicates inline body content
	HTTPBodyTypeInline HTTPBodyType = "Inline"
	// HTTPBodyTypeValueRef indicates body content from a reference
	HTTPBodyTypeValueRef HTTPBodyType = "ValueRef"
)

// ============================================================================
// HTTP Backend Reference
// ============================================================================

// HTTPBackendRef defines how a HTTPRoute forwards a HTTP request.
type HTTPBackendRef struct {
	BackendRef `json:",inline"`

	// Filters defined at this level should be executed if and only if the
	// request is being forwarded to the backend defined here.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Filters []HTTPRouteFilter `json:"filters,omitempty"`
}

// ============================================================================
// HTTP Route Timeouts
// ============================================================================

// HTTPRouteTimeouts defines timeouts that can be configured for an HTTP request.
type HTTPRouteTimeouts struct {
	// Request specifies the maximum duration for a gateway to respond to an HTTP request.
	// +optional
	Request *Duration `json:"request,omitempty"`

	// BackendRequest specifies a timeout for an individual request from the gateway
	// to a backend.
	// +optional
	BackendRequest *Duration `json:"backendRequest,omitempty"`

	// Idle specifies the maximum duration a connection may be idle.
	// +optional
	Idle *Duration `json:"idle,omitempty"`
}

// ============================================================================
// Session Persistence
// ============================================================================

// SessionPersistenceConfig defines session persistence configuration.
type SessionPersistenceConfig struct {
	// Type defines the type of session persistence.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Cookie;Header
	Type SessionPersistenceType `json:"type"`

	// SessionName is the name of the session (cookie name or header name).
	// +optional
	SessionName *string `json:"sessionName,omitempty"`

	// AbsoluteTimeout defines the absolute timeout of the persistent session.
	// +optional
	AbsoluteTimeout *Duration `json:"absoluteTimeout,omitempty"`

	// IdleTimeout defines the idle timeout of the persistent session.
	// +optional
	IdleTimeout *Duration `json:"idleTimeout,omitempty"`
}

// SessionPersistenceType defines the type of session persistence.
// +kubebuilder:validation:Enum=Cookie;Header
type SessionPersistenceType string

const (
	// SessionPersistenceCookie uses cookies for session persistence
	SessionPersistenceCookie SessionPersistenceType = "Cookie"
	// SessionPersistenceHeader uses headers for session persistence
	SessionPersistenceHeader SessionPersistenceType = "Header"
)

// ============================================================================
// HTTP Retry Policy
// ============================================================================

// HTTPRetryPolicy defines retry policy for HTTP requests.
type HTTPRetryPolicy struct {
	// NumRetries is the number of retries to attempt.
	// +kubebuilder:default=1
	// +optional
	NumRetries *int32 `json:"numRetries,omitempty"`

	// RetryOn specifies the conditions under which retry takes place.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	RetryOn []HTTPRetryOn `json:"retryOn,omitempty"`

	// PerTryTimeout specifies the timeout per retry attempt.
	// +optional
	PerTryTimeout *Duration `json:"perTryTimeout,omitempty"`

	// Backoff defines the backoff strategy for retries.
	// +optional
	Backoff *RetryBackoff `json:"backoff,omitempty"`
}

// HTTPRetryOn defines conditions for retry.
// +kubebuilder:validation:Enum=server-error;gateway-error;reset;connect-failure;retriable-client-error;refused-stream;retriable-status-codes;retriable-headers
//
//nolint:lll // kubebuilder validation enum cannot be shortened
type HTTPRetryOn string

const (
	HTTPRetryOnServerError          HTTPRetryOn = "server-error"
	HTTPRetryOnGatewayError         HTTPRetryOn = "gateway-error"
	HTTPRetryOnReset                HTTPRetryOn = "reset"
	HTTPRetryOnConnectFailure       HTTPRetryOn = "connect-failure"
	HTTPRetryOnRetriableClientError HTTPRetryOn = "retriable-client-error"
	HTTPRetryOnRefusedStream        HTTPRetryOn = "refused-stream"
	HTTPRetryOnRetriableStatusCodes HTTPRetryOn = "retriable-status-codes"
	HTTPRetryOnRetriableHeaders     HTTPRetryOn = "retriable-headers"
)

// RetryBackoff defines backoff strategy for retries.
type RetryBackoff struct {
	// BaseInterval is the base interval between retries.
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s|m))+$`
	// +kubebuilder:default="100ms"
	// +optional
	BaseInterval *string `json:"baseInterval,omitempty"`

	// MaxInterval is the maximum interval between retries.
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s|m))+$`
	// +kubebuilder:default="10s"
	// +optional
	MaxInterval *string `json:"maxInterval,omitempty"`
}

// ============================================================================
// HTTPRoute Status
// ============================================================================

// HTTPRouteStatus defines the observed state of HTTPRoute
type HTTPRouteStatus struct {
	RouteStatus `json:",inline"`
}

func init() {
	SchemeBuilder.Register(&HTTPRoute{}, &HTTPRouteList{})
}
