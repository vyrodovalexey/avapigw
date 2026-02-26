// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GraphQLBackendSpec defines the desired state of GraphQLBackend.
type GraphQLBackendSpec struct {
	// Hosts contains the backend host configurations.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Hosts []BackendHost `json:"hosts"`

	// HealthCheck contains health check configuration.
	// +optional
	HealthCheck *HealthCheckConfig `json:"healthCheck,omitempty"`

	// LoadBalancer contains load balancer configuration.
	// +optional
	LoadBalancer *LoadBalancerConfig `json:"loadBalancer,omitempty"`

	// TLS contains TLS configuration for backend connections.
	// +optional
	TLS *BackendTLSConfig `json:"tls,omitempty"`

	// CircuitBreaker configures circuit breaker for this GraphQL backend.
	// +optional
	CircuitBreaker *CircuitBreakerConfig `json:"circuitBreaker,omitempty"`

	// Authentication configures authentication for GraphQL backend connections.
	// +optional
	Authentication *BackendAuthConfig `json:"authentication,omitempty"`

	// MaxSessions configures maximum concurrent sessions for this backend.
	// +optional
	MaxSessions *MaxSessionsConfig `json:"maxSessions,omitempty"`

	// RateLimit configures rate limiting for this backend.
	// +optional
	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`

	// Cache contains caching configuration for this backend.
	// +optional
	Cache *BackendCacheConfig `json:"cache,omitempty"`

	// Encoding contains encoding configuration for this backend.
	// +optional
	Encoding *BackendEncodingConfig `json:"encoding,omitempty"`
}

// GraphQLBackendStatus defines the observed state of GraphQLBackend.
type GraphQLBackendStatus struct {
	// Conditions represent the latest available observations of the GraphQLBackend's state.
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// HealthyHosts is the number of healthy hosts.
	// +optional
	HealthyHosts int `json:"healthyHosts,omitempty"`

	// TotalHosts is the total number of hosts.
	// +optional
	TotalHosts int `json:"totalHosts,omitempty"`

	// LastHealthCheck is the timestamp of the last health check.
	// +optional
	LastHealthCheck *metav1.Time `json:"lastHealthCheck,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gqlbe
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Healthy",type="string",JSONPath=".status.conditions[?(@.type=='Healthy')].status"
// +kubebuilder:printcolumn:name="Hosts",type="string",JSONPath=".status.healthyHosts"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GraphQLBackend is the Schema for the graphqlbackends API.
type GraphQLBackend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GraphQLBackendSpec   `json:"spec,omitempty"`
	Status GraphQLBackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GraphQLBackendList contains a list of GraphQLBackend.
type GraphQLBackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GraphQLBackend `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GraphQLBackend{}, &GraphQLBackendList{})
}
