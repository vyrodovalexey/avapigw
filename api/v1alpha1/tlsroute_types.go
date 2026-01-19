package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// TLSRoute CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tlsr
// +kubebuilder:printcolumn:name="Hostnames",type="string",JSONPath=".spec.hostnames[*]"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// TLSRoute is the Schema for the tlsroutes API.
// TLSRoute provides a way to route TLS requests (passthrough).
type TLSRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TLSRouteSpec   `json:"spec,omitempty"`
	Status TLSRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TLSRouteList contains a list of TLSRoute
type TLSRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSRoute `json:"items"`
}

// TLSRouteSpec defines the desired state of TLSRoute
type TLSRouteSpec struct {
	// ParentRefs references the resources (usually Gateways) that a Route wants
	// to be attached to.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	ParentRefs []ParentRef `json:"parentRefs,omitempty"`

	// Hostnames defines a set of SNI names that should match against the
	// SNI attribute of TLS ClientHello message in TLS handshake.
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:MinItems=1
	Hostnames []Hostname `json:"hostnames"`

	// Rules are a list of TLS matchers and actions.
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:MinItems=1
	Rules []TLSRouteRule `json:"rules"`
}

// TLSRouteRule is the configuration for a given rule.
type TLSRouteRule struct {
	// BackendRefs defines the backend(s) where matching requests should be sent.
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:MinItems=1
	BackendRefs []TLSBackendRef `json:"backendRefs"`
}

// TLSBackendRef defines how a TLSRoute forwards a TLS connection.
type TLSBackendRef struct {
	BackendRef `json:",inline"`
}

// ============================================================================
// TLSRoute Status
// ============================================================================

// TLSRouteStatus defines the observed state of TLSRoute
type TLSRouteStatus struct {
	RouteStatus `json:",inline"`
}

func init() {
	SchemeBuilder.Register(&TLSRoute{}, &TLSRouteList{})
}
