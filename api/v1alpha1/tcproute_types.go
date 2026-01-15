package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// TCPRoute CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tcpr
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// TCPRoute is the Schema for the tcproutes API.
// TCPRoute provides a way to route TCP requests.
type TCPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TCPRouteSpec   `json:"spec,omitempty"`
	Status TCPRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TCPRouteList contains a list of TCPRoute
type TCPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TCPRoute `json:"items"`
}

// TCPRouteSpec defines the desired state of TCPRoute
type TCPRouteSpec struct {
	// ParentRefs references the resources (usually Gateways) that a Route wants
	// to be attached to.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	ParentRefs []ParentRef `json:"parentRefs,omitempty"`

	// Rules are a list of TCP matchers and actions.
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:MinItems=1
	Rules []TCPRouteRule `json:"rules"`
}

// TCPRouteRule is the configuration for a given rule.
type TCPRouteRule struct {
	// BackendRefs defines the backend(s) where matching requests should be sent.
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:MinItems=1
	BackendRefs []TCPBackendRef `json:"backendRefs"`

	// IdleTimeout is the maximum duration a connection may be idle.
	// +optional
	IdleTimeout *Duration `json:"idleTimeout,omitempty"`

	// ConnectTimeout is the maximum duration to wait for a connection to be established.
	// +optional
	ConnectTimeout *Duration `json:"connectTimeout,omitempty"`
}

// TCPBackendRef defines how a TCPRoute forwards a TCP connection.
type TCPBackendRef struct {
	BackendRef `json:",inline"`
}

// ============================================================================
// TCPRoute Status
// ============================================================================

// TCPRouteStatus defines the observed state of TCPRoute
type TCPRouteStatus struct {
	RouteStatus `json:",inline"`
}

func init() {
	SchemeBuilder.Register(&TCPRoute{}, &TCPRouteList{})
}
