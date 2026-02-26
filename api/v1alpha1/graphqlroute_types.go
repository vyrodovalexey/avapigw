// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GraphQLRouteSpec defines the desired state of GraphQLRoute.
type GraphQLRouteSpec struct {
	// Match contains the matching conditions for this route.
	// +optional
	Match []GraphQLRouteMatch `json:"match,omitempty"`

	// Route contains the destination(s) for matched requests.
	// +optional
	Route []RouteDestination `json:"route,omitempty"`

	// Timeout is the request timeout for this route.
	// +optional
	Timeout Duration `json:"timeout,omitempty"`

	// Retries contains retry policy configuration.
	// +optional
	Retries *RetryPolicy `json:"retries,omitempty"`

	// Headers contains header manipulation configuration.
	// +optional
	Headers *HeaderManipulation `json:"headers,omitempty"`

	// RateLimit contains route-level rate limiting configuration.
	// +optional
	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`

	// Cache contains caching configuration.
	// +optional
	Cache *CacheConfig `json:"cache,omitempty"`

	// CORS configures CORS for this GraphQL route.
	// +optional
	CORS *CORSConfig `json:"cors,omitempty"`

	// Security configures security headers for this GraphQL route.
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

	// DepthLimit is the maximum query depth allowed.
	// +kubebuilder:validation:Minimum=0
	// +optional
	DepthLimit int `json:"depthLimit,omitempty"`

	// ComplexityLimit is the maximum query complexity allowed.
	// +kubebuilder:validation:Minimum=0
	// +optional
	ComplexityLimit int `json:"complexityLimit,omitempty"`

	// IntrospectionEnabled controls whether introspection queries are allowed.
	// +optional
	IntrospectionEnabled *bool `json:"introspectionEnabled,omitempty"`

	// AllowedOperations restricts which operation types are allowed (query, mutation, subscription).
	// +optional
	AllowedOperations []string `json:"allowedOperations,omitempty"`
}

// GraphQLRouteMatch represents matching conditions for a GraphQL route.
type GraphQLRouteMatch struct {
	// Path matches the HTTP path for the GraphQL endpoint.
	// +optional
	Path *StringMatch `json:"path,omitempty"`

	// OperationType matches the GraphQL operation type (query, mutation, subscription).
	// +kubebuilder:validation:Enum=query;mutation;subscription
	// +optional
	OperationType string `json:"operationType,omitempty"`

	// OperationName matches the GraphQL operation name.
	// +optional
	OperationName *StringMatch `json:"operationName,omitempty"`

	// Headers matches HTTP headers.
	// +optional
	Headers []GraphQLHeaderMatch `json:"headers,omitempty"`
}

// GraphQLHeaderMatch represents header matching configuration for GraphQL routes.
type GraphQLHeaderMatch struct {
	// Name is the header name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Exact matches the header value exactly.
	// +optional
	Exact string `json:"exact,omitempty"`

	// Prefix matches header values starting with this prefix.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Regex matches header values using a regular expression.
	// +optional
	Regex string `json:"regex,omitempty"`
}

// GraphQLRouteStatus defines the observed state of GraphQLRoute.
type GraphQLRouteStatus struct {
	// Conditions represent the latest available observations of the GraphQLRoute's state.
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
// +kubebuilder:resource:shortName=gqlr
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GraphQLRoute is the Schema for the graphqlroutes API.
type GraphQLRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GraphQLRouteSpec   `json:"spec,omitempty"`
	Status GraphQLRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GraphQLRouteList contains a list of GraphQLRoute.
type GraphQLRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GraphQLRoute `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GraphQLRoute{}, &GraphQLRouteList{})
}
