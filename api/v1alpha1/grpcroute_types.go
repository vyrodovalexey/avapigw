// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GRPCRouteSpec defines the desired state of GRPCRoute.
type GRPCRouteSpec struct {
	// Match contains the matching conditions for this route.
	// +optional
	Match []GRPCRouteMatch `json:"match,omitempty"`

	// Route contains the destination(s) for matched requests.
	// +optional
	Route []RouteDestination `json:"route,omitempty"`

	// Timeout is the request timeout for this route.
	// +optional
	Timeout Duration `json:"timeout,omitempty"`

	// Retries contains gRPC retry policy configuration.
	// +optional
	Retries *GRPCRetryPolicy `json:"retries,omitempty"`

	// Headers contains header manipulation configuration.
	// +optional
	Headers *HeaderManipulation `json:"headers,omitempty"`

	// Mirror contains traffic mirroring configuration.
	// +optional
	Mirror *MirrorConfig `json:"mirror,omitempty"`

	// RateLimit contains route-level rate limiting configuration.
	// +optional
	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`

	// Transform contains gRPC-specific transformation configuration.
	// +optional
	Transform *GRPCTransformConfig `json:"transform,omitempty"`

	// Cache contains caching configuration.
	// +optional
	Cache *CacheConfig `json:"cache,omitempty"`

	// Encoding contains encoding configuration.
	// +optional
	Encoding *EncodingConfig `json:"encoding,omitempty"`

	// CORS configures CORS for this gRPC route.
	// +optional
	CORS *CORSConfig `json:"cors,omitempty"`

	// Security configures security headers for this gRPC route.
	// +optional
	Security *SecurityConfig `json:"security,omitempty"`

	// TLS configures route-level TLS certificate override.
	// +optional
	TLS *RouteTLSConfig `json:"tls,omitempty"`

	// Authentication configures route-level authentication.
	// +optional
	Authentication *AuthenticationConfig `json:"authentication,omitempty"`

	// Authorization configures route-level authorization.
	// +optional
	Authorization *AuthorizationConfig `json:"authorization,omitempty"`

	// MaxSessions configures maximum concurrent sessions for this route.
	// +optional
	MaxSessions *MaxSessionsConfig `json:"maxSessions,omitempty"`

	// RequestLimits configures request size limits for this route.
	// +optional
	RequestLimits *RequestLimitsConfig `json:"requestLimits,omitempty"`
}

// GRPCRouteMatch represents matching conditions for a gRPC route.
type GRPCRouteMatch struct {
	// Service matches the gRPC service name.
	// +optional
	Service *StringMatch `json:"service,omitempty"`

	// Method matches the gRPC method name.
	// +optional
	Method *StringMatch `json:"method,omitempty"`

	// Metadata matches gRPC metadata (headers).
	// +optional
	Metadata []MetadataMatch `json:"metadata,omitempty"`

	// Authority matches the :authority pseudo-header.
	// +optional
	Authority *StringMatch `json:"authority,omitempty"`

	// WithoutHeaders specifies headers that must NOT be present.
	// +optional
	WithoutHeaders []string `json:"withoutHeaders,omitempty"`
}

// MetadataMatch represents gRPC metadata matching configuration.
type MetadataMatch struct {
	// Name is the metadata key name (case-insensitive for gRPC).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Exact matches the metadata value exactly.
	// +optional
	Exact string `json:"exact,omitempty"`

	// Prefix matches metadata values starting with this prefix.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Regex matches metadata values using a regular expression.
	// +optional
	Regex string `json:"regex,omitempty"`

	// Present matches if the metadata key is present (regardless of value).
	// +optional
	Present *bool `json:"present,omitempty"`

	// Absent matches if the metadata key is NOT present.
	// +optional
	Absent *bool `json:"absent,omitempty"`
}

// GRPCTransformConfig represents gRPC-specific transformation configuration.
type GRPCTransformConfig struct {
	// FieldMask contains field mask configuration.
	// +optional
	FieldMask *FieldMaskConfig `json:"fieldMask,omitempty"`

	// Metadata contains metadata manipulation configuration.
	// +optional
	Metadata *MetadataManipulation `json:"metadata,omitempty"`
}

// FieldMaskConfig represents field mask configuration.
type FieldMaskConfig struct {
	// Paths is the list of field paths to include.
	// +optional
	Paths []string `json:"paths,omitempty"`
}

// MetadataManipulation represents metadata manipulation configuration.
type MetadataManipulation struct {
	// Static contains static metadata values.
	// +optional
	Static map[string]string `json:"static,omitempty"`

	// Dynamic contains dynamic metadata values (templates).
	// +optional
	Dynamic map[string]string `json:"dynamic,omitempty"`
}

// GRPCRouteStatus defines the observed state of GRPCRoute.
type GRPCRouteStatus struct {
	// Conditions represent the latest available observations of the GRPCRoute's state.
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
// +kubebuilder:resource:shortName=gr
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GRPCRoute is the Schema for the grpcroutes API.
type GRPCRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GRPCRouteSpec   `json:"spec,omitempty"`
	Status GRPCRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GRPCRouteList contains a list of GRPCRoute.
type GRPCRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GRPCRoute `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GRPCRoute{}, &GRPCRouteList{})
}
