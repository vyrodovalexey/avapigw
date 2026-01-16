// Package route provides shared utilities for route controllers.
package route

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

const (
	// BackendKindService is the kind for Kubernetes Service backends.
	BackendKindService = "Service"
	// BackendKindBackend is the kind for custom Backend CRD backends.
	BackendKindBackend = "Backend"
)

// RouteWithParentRefs is an interface for routes that have parent references.
// This allows generic handling of different route types.
type RouteWithParentRefs interface {
	client.Object
	GetParentRefs() []avapigwv1alpha1.ParentRef
	GetHostnames() []avapigwv1alpha1.Hostname
}

// RouteWithBackendRefs is an interface for routes that have backend references.
type RouteWithBackendRefs interface {
	client.Object
	GetBackendRefs() []BackendRefInfo
}

// BackendRefInfo contains information about a backend reference.
type BackendRefInfo struct {
	Name      string
	Namespace *string
	Kind      *string
	Group     *string
}

// ListenerMatcher defines protocol-specific listener matching logic.
// Each route type implements this interface to define which protocols it supports.
type ListenerMatcher interface {
	// MatchesListener checks if the route matches the given listener.
	// Returns true if the route can be attached to the listener, and a reason message if not.
	MatchesListener(route RouteWithParentRefs, listener avapigwv1alpha1.Listener) (bool, string)
	// SupportedProtocols returns the list of protocols this route type supports.
	SupportedProtocols() []avapigwv1alpha1.ProtocolType
	// NoMatchingListenerMessage returns the error message when no matching listener is found.
	NoMatchingListenerMessage() string
}

// ParentRefValidator validates parent references for routes.
type ParentRefValidator struct {
	client         client.Client
	recorder       record.EventRecorder
	controllerName string
}

// NewParentRefValidator creates a new ParentRefValidator.
func NewParentRefValidator(c client.Client, recorder record.EventRecorder, controllerName string) *ParentRefValidator {
	return &ParentRefValidator{
		client:         c,
		recorder:       recorder,
		controllerName: controllerName,
	}
}

// ValidateParentRefs validates parent references and returns parent statuses.
// This is a generic implementation that works for all route types.
func (v *ParentRefValidator) ValidateParentRefs(
	ctx context.Context,
	route RouteWithParentRefs,
	matcher ListenerMatcher,
) ([]avapigwv1alpha1.RouteParentStatus, error) {
	parentRefs := route.GetParentRefs()
	parentStatuses := make([]avapigwv1alpha1.RouteParentStatus, 0, len(parentRefs))

	for _, parentRef := range parentRefs {
		parentStatus, err := v.validateSingleParentRef(ctx, route, parentRef, matcher)
		if err != nil {
			return nil, err
		}
		parentStatuses = append(parentStatuses, parentStatus)
	}

	return parentStatuses, nil
}

// validateSingleParentRef validates a single parent reference and returns its status.
func (v *ParentRefValidator) validateSingleParentRef(
	ctx context.Context,
	route RouteWithParentRefs,
	parentRef avapigwv1alpha1.ParentRef,
	matcher ListenerMatcher,
) (avapigwv1alpha1.RouteParentStatus, error) {
	logger := log.FromContext(ctx)
	parentStatus := avapigwv1alpha1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: v.controllerName,
	}

	// Determine namespace
	namespace := route.GetNamespace()
	if parentRef.Namespace != nil {
		namespace = *parentRef.Namespace
	}

	// Get the Gateway
	gateway := &avapigwv1alpha1.Gateway{}
	err := v.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: parentRef.Name}, gateway)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Parent Gateway not found",
				"gateway", parentRef.Name,
				"namespace", namespace,
				"route", route.GetName(),
				"routeNamespace", route.GetNamespace(),
			)
			parentStatus.Conditions = v.buildNotFoundConditions(namespace, parentRef.Name)
			return parentStatus, nil
		}
		return parentStatus, fmt.Errorf("failed to get Gateway %s/%s: %w", namespace, parentRef.Name, err)
	}

	// Validate listener match and set conditions
	parentStatus.Conditions = v.buildListenerMatchConditions(route, gateway, parentRef, matcher)
	return parentStatus, nil
}

// buildNotFoundConditions builds conditions for a not-found gateway.
func (v *ParentRefValidator) buildNotFoundConditions(namespace, name string) []avapigwv1alpha1.Condition {
	return []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionTypeAccepted,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             string(avapigwv1alpha1.ReasonNoMatchingParent),
			Message:            fmt.Sprintf("Gateway %s/%s not found", namespace, name),
		},
	}
}

// buildListenerMatchConditions builds conditions based on listener match validation.
func (v *ParentRefValidator) buildListenerMatchConditions(
	route RouteWithParentRefs,
	gateway *avapigwv1alpha1.Gateway,
	parentRef avapigwv1alpha1.ParentRef,
	matcher ListenerMatcher,
) []avapigwv1alpha1.Condition {
	accepted, message := v.validateListenerMatch(route, gateway, parentRef, matcher)
	if accepted {
		return []avapigwv1alpha1.Condition{
			{
				Type:               avapigwv1alpha1.ConditionTypeAccepted,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             string(avapigwv1alpha1.ReasonAccepted),
				Message:            "Route accepted by Gateway",
			},
			{
				Type:               avapigwv1alpha1.ConditionTypeResolvedRefs,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             string(avapigwv1alpha1.ReasonResolvedRefs),
				Message:            "All references resolved",
			},
		}
	}
	return []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionTypeAccepted,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             string(avapigwv1alpha1.ReasonNotAllowedByListeners),
			Message:            message,
		},
	}
}

// validateListenerMatch validates that the route matches a listener on the gateway.
func (v *ParentRefValidator) validateListenerMatch(
	route RouteWithParentRefs,
	gateway *avapigwv1alpha1.Gateway,
	parentRef avapigwv1alpha1.ParentRef,
	matcher ListenerMatcher,
) (matches bool, reason string) {
	// If a specific section (listener) is specified, validate it
	if parentRef.SectionName != nil {
		listenerName := *parentRef.SectionName
		for _, listener := range gateway.Spec.Listeners {
			if listener.Name == listenerName {
				return matcher.MatchesListener(route, listener)
			}
		}
		return false, fmt.Sprintf("Listener %s not found on Gateway", listenerName)
	}

	// No specific listener, check if any matching listener exists
	supportedProtocols := matcher.SupportedProtocols()
	for _, listener := range gateway.Spec.Listeners {
		if containsProtocol(supportedProtocols, listener.Protocol) {
			if matches, _ := matcher.MatchesListener(route, listener); matches {
				return true, ""
			}
		}
	}

	return false, matcher.NoMatchingListenerMessage()
}

// containsProtocol checks if a protocol is in the list of supported protocols.
func containsProtocol(protocols []avapigwv1alpha1.ProtocolType, protocol avapigwv1alpha1.ProtocolType) bool {
	for _, p := range protocols {
		if p == protocol {
			return true
		}
	}
	return false
}

// BackendRefValidator validates backend references for routes.
type BackendRefValidator struct {
	client   client.Client
	recorder record.EventRecorder
}

// NewBackendRefValidator creates a new BackendRefValidator.
func NewBackendRefValidator(c client.Client, recorder record.EventRecorder) *BackendRefValidator {
	return &BackendRefValidator{
		client:   c,
		recorder: recorder,
	}
}

// ValidateBackendRefs validates backend references for a route.
// It checks if the referenced backends (Services or Backend CRDs) exist.
// Missing backends are logged and recorded as events but don't cause errors.
func (v *BackendRefValidator) ValidateBackendRefs(
	ctx context.Context,
	route client.Object,
	backendRefs []BackendRefInfo,
) error {
	routeNamespace := route.GetNamespace()

	for _, backendRef := range backendRefs {
		if err := v.validateSingleBackendRef(ctx, route, backendRef, routeNamespace); err != nil {
			return err
		}
	}

	return nil
}

// validateSingleBackendRef validates a single backend reference.
func (v *BackendRefValidator) validateSingleBackendRef(
	ctx context.Context,
	route client.Object,
	backendRef BackendRefInfo,
	routeNamespace string,
) error {
	namespace := routeNamespace
	if backendRef.Namespace != nil {
		namespace = *backendRef.Namespace
	}

	kind := BackendKindService
	if backendRef.Kind != nil {
		kind = *backendRef.Kind
	}

	group := ""
	if backendRef.Group != nil {
		group = *backendRef.Group
	}

	// Check based on kind
	switch {
	case group == "" && kind == BackendKindService:
		return v.validateServiceBackend(ctx, route, backendRef.Name, namespace, routeNamespace)
	case group == avapigwv1alpha1.GroupVersion.Group && kind == BackendKindBackend:
		return v.validateCustomBackend(ctx, route, backendRef.Name, namespace, routeNamespace)
	default:
		v.logUnsupportedBackend(ctx, route, group, kind, routeNamespace)
	}

	return nil
}

// validateServiceBackend validates a Kubernetes Service backend reference.
func (v *BackendRefValidator) validateServiceBackend(
	ctx context.Context,
	route client.Object,
	name, namespace, routeNamespace string,
) error {
	logger := log.FromContext(ctx)
	svc := &corev1.Service{}
	if err := v.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, svc); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Backend Service not found",
				"service", name,
				"namespace", namespace,
				"route", route.GetName(),
				"routeNamespace", routeNamespace,
			)
			v.recorder.Event(route, corev1.EventTypeWarning, "BackendNotFound",
				fmt.Sprintf("Service %s/%s not found", namespace, name))
			return nil
		}
		return fmt.Errorf("failed to get Service %s/%s: %w", namespace, name, err)
	}
	return nil
}

// validateCustomBackend validates a custom Backend CRD reference.
func (v *BackendRefValidator) validateCustomBackend(
	ctx context.Context,
	route client.Object,
	name, namespace, routeNamespace string,
) error {
	logger := log.FromContext(ctx)
	backend := &avapigwv1alpha1.Backend{}
	if err := v.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, backend); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Backend not found",
				"backend", name,
				"namespace", namespace,
				"route", route.GetName(),
				"routeNamespace", routeNamespace,
			)
			v.recorder.Event(route, corev1.EventTypeWarning, "BackendNotFound",
				fmt.Sprintf("Backend %s/%s not found", namespace, name))
			return nil
		}
		return fmt.Errorf("failed to get Backend %s/%s: %w", namespace, name, err)
	}
	return nil
}

// logUnsupportedBackend logs a warning for unsupported backend kinds.
func (v *BackendRefValidator) logUnsupportedBackend(
	ctx context.Context,
	route client.Object,
	group, kind, routeNamespace string,
) {
	logger := log.FromContext(ctx)
	logger.Info("Unsupported backend kind",
		"group", group,
		"kind", kind,
		"route", route.GetName(),
		"routeNamespace", routeNamespace,
	)
}

// HTTPListenerMatcher implements ListenerMatcher for HTTPRoute.
type HTTPListenerMatcher struct{}

// MatchesListener checks if an HTTPRoute matches the given listener.
func (m *HTTPListenerMatcher) MatchesListener(
	route RouteWithParentRefs,
	listener avapigwv1alpha1.Listener,
) (matches bool, reason string) {
	// Check protocol compatibility
	if listener.Protocol != avapigwv1alpha1.ProtocolHTTP && listener.Protocol != avapigwv1alpha1.ProtocolHTTPS {
		return false, fmt.Sprintf("Listener %s does not support HTTP protocol", listener.Name)
	}
	// Check hostname match
	if !HostnameMatches(route.GetHostnames(), listener.Hostname) {
		return false, fmt.Sprintf("No matching hostname for listener %s", listener.Name)
	}
	return true, ""
}

// SupportedProtocols returns the protocols supported by HTTPRoute.
func (m *HTTPListenerMatcher) SupportedProtocols() []avapigwv1alpha1.ProtocolType {
	return []avapigwv1alpha1.ProtocolType{avapigwv1alpha1.ProtocolHTTP, avapigwv1alpha1.ProtocolHTTPS}
}

// NoMatchingListenerMessage returns the error message when no matching listener is found.
func (m *HTTPListenerMatcher) NoMatchingListenerMessage() string {
	return "No matching HTTP/HTTPS listener found on Gateway"
}

// GRPCListenerMatcher implements ListenerMatcher for GRPCRoute.
type GRPCListenerMatcher struct{}

// MatchesListener checks if a GRPCRoute matches the given listener.
func (m *GRPCListenerMatcher) MatchesListener(
	route RouteWithParentRefs,
	listener avapigwv1alpha1.Listener,
) (matches bool, reason string) {
	// Check protocol compatibility
	if listener.Protocol != avapigwv1alpha1.ProtocolGRPC && listener.Protocol != avapigwv1alpha1.ProtocolGRPCS {
		return false, fmt.Sprintf("Listener %s does not support gRPC protocol", listener.Name)
	}
	// Check hostname match
	if !HostnameMatches(route.GetHostnames(), listener.Hostname) {
		return false, fmt.Sprintf("No matching hostname for listener %s", listener.Name)
	}
	return true, ""
}

// SupportedProtocols returns the protocols supported by GRPCRoute.
func (m *GRPCListenerMatcher) SupportedProtocols() []avapigwv1alpha1.ProtocolType {
	return []avapigwv1alpha1.ProtocolType{avapigwv1alpha1.ProtocolGRPC, avapigwv1alpha1.ProtocolGRPCS}
}

// NoMatchingListenerMessage returns the error message when no matching listener is found.
func (m *GRPCListenerMatcher) NoMatchingListenerMessage() string {
	return "No matching GRPC/GRPCS listener found on Gateway"
}

// TCPListenerMatcher implements ListenerMatcher for TCPRoute.
type TCPListenerMatcher struct {
	// Port is the optional port from the parent reference.
	Port *int32
}

// MatchesListener checks if a TCPRoute matches the given listener.
func (m *TCPListenerMatcher) MatchesListener(
	route RouteWithParentRefs,
	listener avapigwv1alpha1.Listener,
) (matches bool, reason string) {
	// Check protocol compatibility
	if listener.Protocol != avapigwv1alpha1.ProtocolTCP {
		return false, fmt.Sprintf("Listener %s does not support TCP protocol", listener.Name)
	}
	// Check port match if specified
	if m.Port != nil && int32(listener.Port) != *m.Port {
		return false, fmt.Sprintf("Port %d does not match listener %s port %d", *m.Port, listener.Name, listener.Port)
	}
	return true, ""
}

// SupportedProtocols returns the protocols supported by TCPRoute.
func (m *TCPListenerMatcher) SupportedProtocols() []avapigwv1alpha1.ProtocolType {
	return []avapigwv1alpha1.ProtocolType{avapigwv1alpha1.ProtocolTCP}
}

// NoMatchingListenerMessage returns the error message when no matching listener is found.
func (m *TCPListenerMatcher) NoMatchingListenerMessage() string {
	return "No matching TCP listener found on Gateway"
}

// TLSListenerMatcher implements ListenerMatcher for TLSRoute.
type TLSListenerMatcher struct{}

// MatchesListener checks if a TLSRoute matches the given listener.
func (m *TLSListenerMatcher) MatchesListener(
	route RouteWithParentRefs,
	listener avapigwv1alpha1.Listener,
) (matches bool, reason string) {
	// Check protocol compatibility
	if listener.Protocol != avapigwv1alpha1.ProtocolTLS {
		return false, fmt.Sprintf("Listener %s does not support TLS protocol", listener.Name)
	}
	// Check hostname match
	if !HostnameMatches(route.GetHostnames(), listener.Hostname) {
		return false, fmt.Sprintf("No matching hostname for listener %s", listener.Name)
	}
	return true, ""
}

// SupportedProtocols returns the protocols supported by TLSRoute.
func (m *TLSListenerMatcher) SupportedProtocols() []avapigwv1alpha1.ProtocolType {
	return []avapigwv1alpha1.ProtocolType{avapigwv1alpha1.ProtocolTLS}
}

// NoMatchingListenerMessage returns the error message when no matching listener is found.
func (m *TLSListenerMatcher) NoMatchingListenerMessage() string {
	return "No matching TLS listener found on Gateway"
}

// NewTCPListenerMatcherWithPort creates a TCPListenerMatcher with the specified port.
func NewTCPListenerMatcherWithPort(port *int32) *TCPListenerMatcher {
	return &TCPListenerMatcher{Port: port}
}
