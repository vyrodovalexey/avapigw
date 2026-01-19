package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// GRPCRoute CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=grpcr
// +kubebuilder:printcolumn:name="Hostnames",type="string",JSONPath=".spec.hostnames[*]"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GRPCRoute is the Schema for the grpcroutes API.
// GRPCRoute provides a way to route gRPC requests.
type GRPCRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GRPCRouteSpec   `json:"spec,omitempty"`
	Status GRPCRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GRPCRouteList contains a list of GRPCRoute
type GRPCRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GRPCRoute `json:"items"`
}

// GRPCRouteSpec defines the desired state of GRPCRoute
type GRPCRouteSpec struct {
	// ParentRefs references the resources (usually Gateways) that a Route wants
	// to be attached to.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	ParentRefs []ParentRef `json:"parentRefs,omitempty"`

	// Hostnames defines a set of hostnames that should match against the GRPC
	// authority header to select a GRPCRoute used to process the request.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Hostnames []Hostname `json:"hostnames,omitempty"`

	// Rules are a list of GRPC matchers, filters and actions.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Rules []GRPCRouteRule `json:"rules,omitempty"`
}

// GRPCRouteRule defines semantics for matching a gRPC request based on
// conditions (matches), processing it (filters), and forwarding the request
// to an API object (backendRefs).
type GRPCRouteRule struct {
	// Matches define conditions used for matching the rule against incoming
	// gRPC requests. Each match is independent, i.e. this rule will be matched
	// if any one of the matches is satisfied.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Matches []GRPCRouteMatch `json:"matches,omitempty"`

	// Filters define the filters that are applied to requests that match this rule.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Filters []GRPCRouteFilter `json:"filters,omitempty"`

	// BackendRefs defines the backend(s) where matching requests should be sent.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	BackendRefs []GRPCBackendRef `json:"backendRefs,omitempty"`

	// SessionAffinity defines session affinity configuration for this rule.
	// +optional
	SessionAffinity *GRPCSessionAffinityConfig `json:"sessionAffinity,omitempty"`

	// RetryPolicy defines the retry policy for this rule.
	// +optional
	RetryPolicy *GRPCRetryPolicy `json:"retryPolicy,omitempty"`
}

// GRPCRouteMatch defines the predicate used to match requests to a given action.
type GRPCRouteMatch struct {
	// Method specifies a gRPC request service/method matcher.
	// +optional
	Method *GRPCMethodMatch `json:"method,omitempty"`

	// Headers specifies gRPC request header matchers.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Headers []GRPCHeaderMatch `json:"headers,omitempty"`
}

// GRPCMethodMatch describes how to select a gRPC route by matching the gRPC
// request service and/or method.
type GRPCMethodMatch struct {
	// Type specifies how to match against the service and/or method.
	// +kubebuilder:validation:Enum=Exact;RegularExpression
	// +kubebuilder:default=Exact
	// +optional
	Type *GRPCMethodMatchType `json:"type,omitempty"`

	// Service is the name of the gRPC service to match against.
	// If not specified, matches all services.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Service *string `json:"service,omitempty"`

	// Method is the name of the gRPC method to match against.
	// If not specified, matches all methods.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Method *string `json:"method,omitempty"`
}

// GRPCMethodMatchType specifies the semantics of how gRPC methods and services
// should be compared.
// +kubebuilder:validation:Enum=Exact;RegularExpression
type GRPCMethodMatchType string

const (
	// GRPCMethodMatchExact matches the service/method exactly
	GRPCMethodMatchExact GRPCMethodMatchType = "Exact"
	// GRPCMethodMatchRegularExpression matches based on a regular expression
	GRPCMethodMatchRegularExpression GRPCMethodMatchType = "RegularExpression"
)

// GRPCHeaderMatch describes how to select a gRPC route by matching gRPC request headers.
type GRPCHeaderMatch struct {
	// Type specifies how to match against the value of the header.
	// +kubebuilder:validation:Enum=Exact;RegularExpression
	// +kubebuilder:default=Exact
	// +optional
	Type *HeaderMatchType `json:"type,omitempty"`

	// Name is the name of the gRPC metadata header to be matched.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Value is the value of gRPC metadata header to be matched.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Value string `json:"value"`
}

// ============================================================================
// GRPC Route Filters
// ============================================================================

// GRPCRouteFilter defines processing steps that must be completed during the
// request or response lifecycle.
type GRPCRouteFilter struct {
	// Type identifies the type of filter to apply.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=RequestHeaderModifier;ResponseHeaderModifier;RequestMirror;ExtensionRef
	Type GRPCRouteFilterType `json:"type"`

	// RequestHeaderModifier defines a schema for a filter that modifies request headers.
	// +optional
	RequestHeaderModifier *HTTPHeaderFilter `json:"requestHeaderModifier,omitempty"`

	// ResponseHeaderModifier defines a schema for a filter that modifies response headers.
	// +optional
	ResponseHeaderModifier *HTTPHeaderFilter `json:"responseHeaderModifier,omitempty"`

	// RequestMirror defines a schema for a filter that mirrors requests.
	// +optional
	RequestMirror *GRPCRequestMirrorFilter `json:"requestMirror,omitempty"`

	// ExtensionRef is an optional, implementation-specific extension to the
	// "filter" behavior.
	// +optional
	ExtensionRef *LocalObjectReference `json:"extensionRef,omitempty"`
}

// GRPCRouteFilterType identifies a type of GRPCRoute filter.
// +kubebuilder:validation:Enum=RequestHeaderModifier;ResponseHeaderModifier;RequestMirror;ExtensionRef
type GRPCRouteFilterType string

const (
	// GRPCRouteFilterRequestHeaderModifier modifies request headers
	GRPCRouteFilterRequestHeaderModifier GRPCRouteFilterType = "RequestHeaderModifier"
	// GRPCRouteFilterResponseHeaderModifier modifies response headers
	GRPCRouteFilterResponseHeaderModifier GRPCRouteFilterType = "ResponseHeaderModifier"
	// GRPCRouteFilterRequestMirror mirrors requests to another backend
	GRPCRouteFilterRequestMirror GRPCRouteFilterType = "RequestMirror"
	// GRPCRouteFilterExtensionRef references an extension filter
	GRPCRouteFilterExtensionRef GRPCRouteFilterType = "ExtensionRef"
)

// GRPCRequestMirrorFilter defines configuration for the RequestMirror filter.
type GRPCRequestMirrorFilter struct {
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

// ============================================================================
// GRPC Backend Reference
// ============================================================================

// GRPCBackendRef defines how a GRPCRoute forwards a gRPC request.
type GRPCBackendRef struct {
	BackendRef `json:",inline"`

	// Filters defined at this level should be executed if and only if the
	// request is being forwarded to the backend defined here.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Filters []GRPCRouteFilter `json:"filters,omitempty"`
}

// ============================================================================
// GRPC Session Affinity
// ============================================================================

// GRPCSessionAffinityConfig defines session affinity configuration for gRPC.
type GRPCSessionAffinityConfig struct {
	// Type defines the type of session affinity.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Header;Cookie
	Type GRPCSessionAffinityType `json:"type"`

	// Header defines header-based session affinity configuration.
	// +optional
	Header *GRPCSessionAffinityHeaderConfig `json:"header,omitempty"`

	// Cookie defines cookie-based session affinity configuration.
	// +optional
	Cookie *GRPCSessionAffinityCookieConfig `json:"cookie,omitempty"`

	// AbsoluteTimeout defines the absolute timeout of the persistent session.
	// +optional
	AbsoluteTimeout *Duration `json:"absoluteTimeout,omitempty"`

	// IdleTimeout defines the idle timeout of the persistent session.
	// +optional
	IdleTimeout *Duration `json:"idleTimeout,omitempty"`
}

// GRPCSessionAffinityType defines the type of session affinity for gRPC.
// +kubebuilder:validation:Enum=Header;Cookie
type GRPCSessionAffinityType string

const (
	// GRPCSessionAffinityTypeHeader uses headers for session affinity
	GRPCSessionAffinityTypeHeader GRPCSessionAffinityType = "Header"
	// GRPCSessionAffinityTypeCookie uses cookies for session affinity
	GRPCSessionAffinityTypeCookie GRPCSessionAffinityType = "Cookie"
)

// GRPCSessionAffinityHeaderConfig defines header-based session affinity.
type GRPCSessionAffinityHeaderConfig struct {
	// Name is the name of the header to use for session affinity.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Name string `json:"name"`
}

// GRPCSessionAffinityCookieConfig defines cookie-based session affinity.
type GRPCSessionAffinityCookieConfig struct {
	// Name is the name of the cookie to use for session affinity.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Name string `json:"name"`

	// Path is the path of the cookie.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Path *string `json:"path,omitempty"`

	// TTL is the time-to-live of the cookie.
	// +optional
	TTL *Duration `json:"ttl,omitempty"`
}

// ============================================================================
// GRPC Retry Policy
// ============================================================================

// GRPCRetryPolicy defines retry policy for gRPC requests.
type GRPCRetryPolicy struct {
	// NumRetries is the number of retries to attempt.
	// +kubebuilder:default=1
	// +optional
	NumRetries *int32 `json:"numRetries,omitempty"`

	// RetryOn specifies the gRPC status codes under which retry takes place.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	RetryOn []GRPCRetryOn `json:"retryOn,omitempty"`

	// PerTryTimeout specifies the timeout per retry attempt.
	// +optional
	PerTryTimeout *Duration `json:"perTryTimeout,omitempty"`

	// Backoff defines the backoff strategy for retries.
	// +optional
	Backoff *RetryBackoff `json:"backoff,omitempty"`
}

// GRPCRetryOn defines gRPC status codes for retry.
// +kubebuilder:validation:Enum=cancelled;deadline-exceeded;internal;resource-exhausted;unavailable
type GRPCRetryOn string

const (
	GRPCRetryOnCancelled         GRPCRetryOn = "cancelled"
	GRPCRetryOnDeadlineExceeded  GRPCRetryOn = "deadline-exceeded"
	GRPCRetryOnInternal          GRPCRetryOn = "internal"
	GRPCRetryOnResourceExhausted GRPCRetryOn = "resource-exhausted"
	GRPCRetryOnUnavailable       GRPCRetryOn = "unavailable"
)

// ============================================================================
// GRPCRoute Status
// ============================================================================

// GRPCRouteStatus defines the observed state of GRPCRoute
type GRPCRouteStatus struct {
	RouteStatus `json:",inline"`
}

func init() {
	SchemeBuilder.Register(&GRPCRoute{}, &GRPCRouteList{})
}
