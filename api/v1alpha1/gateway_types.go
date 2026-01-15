package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// Gateway CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gw
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Listeners",type="integer",JSONPath=".status.listenersCount"
// +kubebuilder:printcolumn:name="Addresses",type="string",JSONPath=".status.addresses[*].value"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Gateway is the Schema for the gateways API.
// Gateway represents an instance of a service-traffic handling infrastructure
// by binding Listeners to a set of IP addresses.
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GatewaySpec   `json:"spec,omitempty"`
	Status GatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GatewayList contains a list of Gateway
type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

// GatewaySpec defines the desired state of Gateway
type GatewaySpec struct {
	// Selector specifies a set of pod labels used to select the gateway pods
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Listeners associated with this Gateway. Listeners define logical endpoints
	// that are bound on this Gateway's addresses.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	Listeners []Listener `json:"listeners"`

	// Addresses requested for this Gateway. This is optional and behavior can
	// depend on the implementation.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Addresses []GatewayAddress `json:"addresses,omitempty"`

	// Infrastructure defines infrastructure level attributes about this Gateway instance
	// +optional
	Infrastructure *GatewayInfrastructure `json:"infrastructure,omitempty"`
}

// Listener embodies the concept of a logical endpoint where a Gateway accepts
// network connections.
type Listener struct {
	// Name is the name of the Listener. This name MUST be unique within a Gateway.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Hostname specifies the virtual hostname to match for protocol types that
	// define this concept. When unspecified, all hostnames are matched.
	// +optional
	Hostname *Hostname `json:"hostname,omitempty"`

	// Port is the network port. Multiple listeners may use the same port,
	// subject to the Listener compatibility rules.
	// +kubebuilder:validation:Required
	Port PortNumber `json:"port"`

	// Protocol specifies the network protocol this listener expects to receive.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=HTTP;HTTPS;GRPC;GRPCS;TCP;TLS;UDP
	Protocol ProtocolType `json:"protocol"`

	// TLS is the TLS configuration for the Listener. This field is required if
	// the Protocol field is "HTTPS", "GRPCS", or "TLS".
	// +optional
	TLS *GatewayTLSConfig `json:"tls,omitempty"`

	// AllowedRoutes defines the types of routes that MAY be attached to a
	// Listener and the trusted namespaces where those Route resources MAY be present.
	// +optional
	AllowedRoutes *AllowedRoutes `json:"allowedRoutes,omitempty"`
}

// GatewayTLSConfig describes a TLS configuration for a Gateway Listener
type GatewayTLSConfig struct {
	// Mode defines the TLS behavior for the TLS session initiated by the client.
	// +kubebuilder:validation:Enum=Terminate;Passthrough
	// +kubebuilder:default=Terminate
	// +optional
	Mode *TLSModeType `json:"mode,omitempty"`

	// CertificateRefs contains a series of references to Kubernetes objects that
	// contain TLS certificates and private keys.
	// +kubebuilder:validation:MaxItems=64
	// +optional
	CertificateRefs []SecretObjectReference `json:"certificateRefs,omitempty"`

	// Options are a list of key/value pairs to enable extended TLS configuration
	// +kubebuilder:validation:MaxProperties=16
	// +optional
	Options map[string]string `json:"options,omitempty"`
}

// TLSModeType defines the mode of TLS termination
// +kubebuilder:validation:Enum=Terminate;Passthrough
type TLSModeType string

const (
	// TLSModeTerminate indicates TLS should be terminated at the Gateway
	TLSModeTerminate TLSModeType = "Terminate"
	// TLSModePassthrough indicates TLS should be passed through to the backend
	TLSModePassthrough TLSModeType = "Passthrough"
)

// AllowedRoutes defines which Routes may be attached to this Listener
type AllowedRoutes struct {
	// Namespaces indicates namespaces from which Routes may be attached to this
	// Listener.
	// +optional
	Namespaces *RouteNamespaces `json:"namespaces,omitempty"`

	// Kinds specifies the groups and kinds of Routes that are allowed to bind
	// to this Gateway Listener.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Kinds []RouteGroupKind `json:"kinds,omitempty"`
}

// RouteNamespaces indicate which namespaces Routes should be selected from
type RouteNamespaces struct {
	// From indicates where Routes will be selected for this Gateway.
	// +kubebuilder:validation:Enum=All;Selector;Same
	// +kubebuilder:default=Same
	// +optional
	From *FromNamespaces `json:"from,omitempty"`

	// Selector must be specified when From is set to "Selector". In that case,
	// only Routes in Namespaces matching this Selector will be selected by this Gateway.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// FromNamespaces specifies namespace selection for routes
// +kubebuilder:validation:Enum=All;Selector;Same
type FromNamespaces string

const (
	// NamespacesFromAll indicates routes from all namespaces are allowed
	NamespacesFromAll FromNamespaces = "All"
	// NamespacesFromSelector indicates routes from namespaces matching selector are allowed
	NamespacesFromSelector FromNamespaces = "Selector"
	// NamespacesFromSame indicates only routes from the same namespace are allowed
	NamespacesFromSame FromNamespaces = "Same"
)

// RouteGroupKind indicates the group and kind of a Route resource
type RouteGroupKind struct {
	// Group is the group of the Route
	// +kubebuilder:default="avapigw.vyrodovalexey.github.com"
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Group *string `json:"group,omitempty"`

	// Kind is the kind of the Route
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind"`
}

// GatewayAddress describes an address that can be bound to a Gateway
type GatewayAddress struct {
	// Type of the address
	// +kubebuilder:validation:Enum=IPAddress;Hostname;NamedAddress
	// +kubebuilder:default=IPAddress
	// +optional
	Type *AddressType `json:"type,omitempty"`

	// Value of the address. The validity of the values will depend on the type.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Value string `json:"value"`
}

// AddressType defines the type of address
// +kubebuilder:validation:Enum=IPAddress;Hostname;NamedAddress
type AddressType string

const (
	// AddressTypeIPAddress indicates an IP address
	AddressTypeIPAddress AddressType = "IPAddress"
	// AddressTypeHostname indicates a hostname
	AddressTypeHostname AddressType = "Hostname"
	// AddressTypeNamedAddress indicates a named address
	AddressTypeNamedAddress AddressType = "NamedAddress"
)

// GatewayInfrastructure defines infrastructure level attributes about a Gateway
type GatewayInfrastructure struct {
	// Labels that SHOULD be applied to any resources created in response to this Gateway
	// +kubebuilder:validation:MaxProperties=8
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations that SHOULD be applied to any resources created in response to this Gateway
	// +kubebuilder:validation:MaxProperties=8
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// ParametersRef is a reference to a resource that contains the configuration
	// parameters corresponding to the Gateway
	// +optional
	ParametersRef *LocalObjectReference `json:"parametersRef,omitempty"`
}

// ============================================================================
// Gateway Status
// ============================================================================

// GatewayStatus defines the observed state of Gateway
type GatewayStatus struct {
	Status `json:",inline"`

	// Addresses lists the network addresses that have been bound to the Gateway
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Addresses []GatewayStatusAddress `json:"addresses,omitempty"`

	// Listeners provides status for each unique listener port defined in the Spec
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	// +optional
	Listeners []ListenerStatus `json:"listeners,omitempty"`

	// ListenersCount is the number of listeners configured
	ListenersCount int32 `json:"listenersCount,omitempty"`
}

// GatewayStatusAddress describes a network address that is bound to a Gateway
type GatewayStatusAddress struct {
	// Type of the address
	// +kubebuilder:validation:Enum=IPAddress;Hostname;NamedAddress
	// +kubebuilder:default=IPAddress
	// +optional
	Type *AddressType `json:"type,omitempty"`

	// Value of the address
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Value string `json:"value"`
}

// ListenerStatus is the status associated with a Listener
type ListenerStatus struct {
	// Name is the name of the Listener that this status corresponds to
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// SupportedKinds is the list of route kinds that MAY be attached to a listener
	// +kubebuilder:validation:MaxItems=8
	// +optional
	SupportedKinds []RouteGroupKind `json:"supportedKinds,omitempty"`

	// AttachedRoutes represents the total number of Routes that have been
	// successfully attached to this Listener
	AttachedRoutes int32 `json:"attachedRoutes"`

	// Conditions describe the current condition of this listener
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`
}

func init() {
	SchemeBuilder.Register(&Gateway{}, &GatewayList{})
}
