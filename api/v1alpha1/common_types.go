package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// Phase Status Types
// ============================================================================

// PhaseStatus represents the phase status of a resource
type PhaseStatus string

const (
	// PhaseStatusPending indicates the resource is pending
	PhaseStatusPending PhaseStatus = "Pending"
	// PhaseStatusReady indicates the resource is ready
	PhaseStatusReady PhaseStatus = "Ready"
	// PhaseStatusError indicates the resource has an error
	PhaseStatusError PhaseStatus = "Error"
	// PhaseStatusReconciling indicates the resource is being reconciled
	PhaseStatusReconciling PhaseStatus = "Reconciling"
	// PhaseStatusDegraded indicates the resource is in a degraded state
	PhaseStatusDegraded PhaseStatus = "Degraded"
)

// ============================================================================
// Condition Types
// ============================================================================

// ConditionType represents the type of condition
type ConditionType string

const (
	// ConditionTypeReady indicates the resource is ready
	ConditionTypeReady ConditionType = "Ready"
	// ConditionTypeReconciled indicates the resource has been reconciled
	ConditionTypeReconciled ConditionType = "Reconciled"
	// ConditionTypeError indicates an error condition
	ConditionTypeError ConditionType = "Error"
	// ConditionTypeAccepted indicates the resource configuration is accepted
	ConditionTypeAccepted ConditionType = "Accepted"
	// ConditionTypeProgrammed indicates the resource has been programmed
	ConditionTypeProgrammed ConditionType = "Programmed"
	// ConditionTypeResolvedRefs indicates all references have been resolved
	ConditionTypeResolvedRefs ConditionType = "ResolvedRefs"
	// ConditionTypeDegraded indicates the resource is in a degraded state
	ConditionTypeDegraded ConditionType = "Degraded"
	// ConditionTypeAvailable indicates the resource is available
	ConditionTypeAvailable ConditionType = "Available"
)

// ConditionReason represents the reason for a condition
type ConditionReason string

const (
	// ReasonAccepted indicates the resource was accepted
	ReasonAccepted ConditionReason = "Accepted"
	// ReasonNotAccepted indicates the resource was not accepted
	ReasonNotAccepted ConditionReason = "NotAccepted"
	// ReasonProgrammed indicates the resource was programmed
	ReasonProgrammed ConditionReason = "Programmed"
	// ReasonNotProgrammed indicates the resource was not programmed
	ReasonNotProgrammed ConditionReason = "NotProgrammed"
	// ReasonResolvedRefs indicates all references were resolved
	ReasonResolvedRefs ConditionReason = "ResolvedRefs"
	// ReasonInvalidRef indicates an invalid reference
	ReasonInvalidRef ConditionReason = "InvalidRef"
	// ReasonRefNotFound indicates a reference was not found
	ReasonRefNotFound ConditionReason = "RefNotFound"
	// ReasonReady indicates the resource is ready
	ReasonReady ConditionReason = "Ready"
	// ReasonNotReady indicates the resource is not ready
	ReasonNotReady ConditionReason = "NotReady"
	// ReasonReconciling indicates the resource is being reconciled
	ReasonReconciling ConditionReason = "Reconciling"
	// ReasonError indicates an error occurred
	ReasonError ConditionReason = "Error"
	// ReasonDegraded indicates the resource is degraded
	ReasonDegraded ConditionReason = "Degraded"
	// ReasonNoMatchingParent indicates no matching parent was found
	ReasonNoMatchingParent ConditionReason = "NoMatchingParent"
	// ReasonNoMatchingListenerHostname indicates no matching listener hostname
	ReasonNoMatchingListenerHostname ConditionReason = "NoMatchingListenerHostname"
	// ReasonNotAllowedByListeners indicates route not allowed by listeners
	ReasonNotAllowedByListeners ConditionReason = "NotAllowedByListeners"
	// ReasonBackendNotFound indicates backend was not found
	ReasonBackendNotFound ConditionReason = "BackendNotFound"
	// ReasonUnsupportedValue indicates an unsupported value
	ReasonUnsupportedValue ConditionReason = "UnsupportedValue"
)

// ============================================================================
// Condition
// ============================================================================

// Condition represents a condition of a resource
type Condition struct {
	// Type of condition
	// +kubebuilder:validation:Required
	Type ConditionType `json:"type"`

	// Status of the condition, one of True, False, Unknown
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=True;False;Unknown
	Status metav1.ConditionStatus `json:"status"`

	// LastTransitionTime is the last time the condition transitioned from one status to another
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=date-time
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// Reason is a brief reason for the condition's last transition
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:MinLength=1
	Reason string `json:"reason"`

	// Message is a human-readable message indicating details about the transition
	// +kubebuilder:validation:MaxLength=32768
	Message string `json:"message,omitempty"`

	// ObservedGeneration represents the .metadata.generation that the condition was set based upon
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ============================================================================
// Status
// ============================================================================

// Status defines common status fields for resources
type Status struct {
	// Phase represents the current phase of the resource
	// +kubebuilder:validation:Enum=Pending;Ready;Error;Reconciling;Degraded
	Phase PhaseStatus `json:"phase,omitempty"`

	// Conditions represent the latest available observations of an object's state
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []Condition `json:"conditions,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed resource
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastReconciledTime is the last time the resource was reconciled
	LastReconciledTime *metav1.Time `json:"lastReconciledTime,omitempty"`
}

// GetCondition returns the condition with the provided type
func (s *Status) GetCondition(conditionType ConditionType) *Condition {
	for i := range s.Conditions {
		if s.Conditions[i].Type == conditionType {
			return &s.Conditions[i]
		}
	}
	return nil
}

// SetCondition sets the condition with the provided type
func (s *Status) SetCondition(conditionType ConditionType, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := s.GetCondition(conditionType)
	if condition == nil {
		s.Conditions = append(s.Conditions, Condition{
			Type:               conditionType,
			Status:             status,
			LastTransitionTime: now,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: s.ObservedGeneration,
		})
		return
	}

	if condition.Status != status {
		condition.Status = status
		condition.LastTransitionTime = now
	}
	condition.Reason = reason
	condition.Message = message
	condition.ObservedGeneration = s.ObservedGeneration
}

// ============================================================================
// Reference Types
// ============================================================================

// LocalObjectReference identifies an API object within the namespace of the referrer
type LocalObjectReference struct {
	// Name is the name of the referent
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// SecretObjectReference identifies a Secret object within a namespace
type SecretObjectReference struct {
	// Name is the name of the secret
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the namespace of the secret
	// If not specified, the namespace of the referrer is used
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace *string `json:"namespace,omitempty"`
}

// TargetRef identifies an API object to apply a policy to.
// This is used for policy attachment pattern.
type TargetRef struct {
	// Group is the group of the target resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	Group string `json:"group"`

	// Kind is the kind of the target resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind"`

	// Name is the name of the target resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the namespace of the target resource
	// When unspecified, the local namespace is inferred
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// SectionName is the name of a section within the target resource
	// When unspecified, this targets the entire resource
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	SectionName *string `json:"sectionName,omitempty"`
}

// ParentRef identifies a parent resource for route binding
type ParentRef struct {
	// Group is the group of the parent resource
	// Defaults to "avapigw.vyrodovalexey.github.com"
	// +kubebuilder:default="avapigw.vyrodovalexey.github.com"
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Group *string `json:"group,omitempty"`

	// Kind is the kind of the parent resource
	// Defaults to "Gateway"
	// +kubebuilder:default="Gateway"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Kind *string `json:"kind,omitempty"`

	// Name is the name of the parent resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the namespace of the parent resource
	// When unspecified, the local namespace is inferred
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// SectionName is the name of a section within the parent resource
	// This is typically the listener name for Gateway
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	SectionName *string `json:"sectionName,omitempty"`

	// Port is the network port this Route targets
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port *int32 `json:"port,omitempty"`
}

// BackendRef identifies a backend to forward traffic to
type BackendRef struct {
	// Group is the group of the backend resource
	// Empty string means the core API group
	// +kubebuilder:default=""
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Group *string `json:"group,omitempty"`

	// Kind is the kind of the backend resource
	// Defaults to "Service"
	// +kubebuilder:default="Service"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Kind *string `json:"kind,omitempty"`

	// Name is the name of the backend resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the namespace of the backend resource
	// When unspecified, the local namespace is inferred
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// Port is the port of the backend service
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port *int32 `json:"port,omitempty"`

	// Weight specifies the proportion of traffic to forward to this backend
	// Defaults to 1
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000000
	// +optional
	Weight *int32 `json:"weight,omitempty"`
}

// ============================================================================
// Route Status Types
// ============================================================================

// RouteParentStatus describes the status of a route with respect to an associated parent
type RouteParentStatus struct {
	// ParentRef corresponds with a ParentRef in the spec that this status describes
	// +kubebuilder:validation:Required
	ParentRef ParentRef `json:"parentRef"`

	// ControllerName is the name of the controller that wrote this status
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	ControllerName string `json:"controllerName"`

	// Conditions describes the status of the route with respect to the Gateway
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []Condition `json:"conditions,omitempty"`
}

// RouteStatus defines the common status for all route types
type RouteStatus struct {
	// Parents is a list of parent resources (usually Gateways) that are associated
	// with the route, and the status of the route with respect to each parent
	// +kubebuilder:validation:MaxItems=32
	Parents []RouteParentStatus `json:"parents,omitempty"`
}

// ============================================================================
// Duration Type
// ============================================================================

// Duration is a string representation of a duration (e.g., "30s", "5m", "1h")
type Duration string

// ============================================================================
// Common Spec Types
// ============================================================================

// CommonSpec defines common spec fields for resources
// This can be embedded in specific resource specs
type CommonSpec struct {
	// ResourceID is a unique identifier for the resource
	ResourceID string `json:"resourceID,omitempty"`

	// Labels are key-value pairs that can be attached to resources
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations are key-value pairs that can be attached to resources
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ============================================================================
// Header Modifier Types
// ============================================================================

// HTTPHeader represents an HTTP header name and value
type HTTPHeader struct {
	// Name is the name of the HTTP header
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+$`
	Name string `json:"name"`

	// Value is the value of the HTTP header
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=4096
	Value string `json:"value"`
}

// HTTPHeaderFilter defines a filter that modifies HTTP headers
type HTTPHeaderFilter struct {
	// Set overwrites the request/response with the given header (name, value)
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Set []HTTPHeader `json:"set,omitempty"`

	// Add adds the given header(s) (name, value) to the request/response
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Add []HTTPHeader `json:"add,omitempty"`

	// Remove removes the given header(s) from the request/response
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Remove []string `json:"remove,omitempty"`
}

// ============================================================================
// Hostname Type
// ============================================================================

// Hostname is a DNS hostname
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type Hostname string

// PreciseHostname is a fully qualified DNS hostname without wildcards
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type PreciseHostname string

// ============================================================================
// Port Number Type
// ============================================================================

// PortNumber defines a network port
// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:Maximum=65535
type PortNumber int32

// ============================================================================
// Protocol Type
// ============================================================================

// ProtocolType defines the protocol for a listener
// +kubebuilder:validation:Enum=HTTP;HTTPS;GRPC;GRPCS;TCP;TLS;UDP
type ProtocolType string

const (
	// ProtocolHTTP indicates HTTP protocol
	ProtocolHTTP ProtocolType = "HTTP"
	// ProtocolHTTPS indicates HTTPS protocol
	ProtocolHTTPS ProtocolType = "HTTPS"
	// ProtocolGRPC indicates gRPC protocol
	ProtocolGRPC ProtocolType = "GRPC"
	// ProtocolGRPCS indicates gRPC over TLS protocol
	ProtocolGRPCS ProtocolType = "GRPCS"
	// ProtocolTCP indicates TCP protocol
	ProtocolTCP ProtocolType = "TCP"
	// ProtocolTLS indicates TLS protocol (passthrough)
	ProtocolTLS ProtocolType = "TLS"
	// ProtocolUDP indicates UDP protocol
	ProtocolUDP ProtocolType = "UDP"
)
