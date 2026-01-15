// Package validator provides validation logic for CRD webhooks.
package validator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Backend reference kind constants
const (
	refKindService = "Service"
	refKindBackend = "Backend"
)

// ReferenceValidator provides methods for validating cross-resource references
type ReferenceValidator struct {
	Client client.Client
}

// NewReferenceValidator creates a new ReferenceValidator
func NewReferenceValidator(c client.Client) *ReferenceValidator {
	return &ReferenceValidator{
		Client: c,
	}
}

// ValidateGatewayExists validates that a Gateway exists
func (r *ReferenceValidator) ValidateGatewayExists(ctx context.Context, namespace, name string) error {
	gateway := &avapigwv1alpha1.Gateway{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, gateway); err != nil {
		return fmt.Errorf("gateway %s/%s not found: %w", namespace, name, err)
	}
	return nil
}

// ValidateGatewayListenerExists validates that a Gateway listener exists
func (r *ReferenceValidator) ValidateGatewayListenerExists(ctx context.Context, namespace, name, listenerName string) error {
	gateway := &avapigwv1alpha1.Gateway{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, gateway); err != nil {
		return fmt.Errorf("gateway %s/%s not found: %w", namespace, name, err)
	}

	for _, listener := range gateway.Spec.Listeners {
		if listener.Name == listenerName {
			return nil
		}
	}

	return fmt.Errorf("listener %q not found in gateway %s/%s", listenerName, namespace, name)
}

// ValidateGatewayHasProtocol validates that a Gateway has a listener with the specified protocol
func (r *ReferenceValidator) ValidateGatewayHasProtocol(ctx context.Context, namespace, name string, protocol avapigwv1alpha1.ProtocolType) error {
	gateway := &avapigwv1alpha1.Gateway{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, gateway); err != nil {
		return fmt.Errorf("gateway %s/%s not found: %w", namespace, name, err)
	}

	for _, listener := range gateway.Spec.Listeners {
		if listener.Protocol == protocol {
			return nil
		}
	}

	return fmt.Errorf("gateway %s/%s has no listener with protocol %s", namespace, name, protocol)
}

// ValidateGatewayListenerHasProtocol validates that a specific Gateway listener has the specified protocol
func (r *ReferenceValidator) ValidateGatewayListenerHasProtocol(ctx context.Context, namespace, name, listenerName string, protocols ...avapigwv1alpha1.ProtocolType) error {
	gateway := &avapigwv1alpha1.Gateway{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, gateway); err != nil {
		return fmt.Errorf("gateway %s/%s not found: %w", namespace, name, err)
	}

	for _, listener := range gateway.Spec.Listeners {
		if listener.Name == listenerName {
			for _, protocol := range protocols {
				if listener.Protocol == protocol {
					return nil
				}
			}
			return fmt.Errorf("listener %q in gateway %s/%s has protocol %s, expected one of %v",
				listenerName, namespace, name, listener.Protocol, protocols)
		}
	}

	return fmt.Errorf("listener %q not found in gateway %s/%s", listenerName, namespace, name)
}

// ValidateGatewayListenerHasTLSPassthrough validates that a Gateway listener has TLS passthrough mode
func (r *ReferenceValidator) ValidateGatewayListenerHasTLSPassthrough(ctx context.Context, namespace, name, listenerName string) error {
	gateway := &avapigwv1alpha1.Gateway{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, gateway); err != nil {
		return fmt.Errorf("gateway %s/%s not found: %w", namespace, name, err)
	}

	for _, listener := range gateway.Spec.Listeners {
		if listener.Name == listenerName {
			if listener.Protocol != avapigwv1alpha1.ProtocolTLS {
				return fmt.Errorf("listener %q in gateway %s/%s has protocol %s, expected TLS for passthrough",
					listenerName, namespace, name, listener.Protocol)
			}
			if listener.TLS != nil && listener.TLS.Mode != nil && *listener.TLS.Mode == avapigwv1alpha1.TLSModePassthrough {
				return nil
			}
			return fmt.Errorf("listener %q in gateway %s/%s is not configured for TLS passthrough",
				listenerName, namespace, name)
		}
	}

	return fmt.Errorf("listener %q not found in gateway %s/%s", listenerName, namespace, name)
}

// ValidateServiceExists validates that a Kubernetes Service exists
func (r *ReferenceValidator) ValidateServiceExists(ctx context.Context, namespace, name string) error {
	service := &corev1.Service{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, service); err != nil {
		return fmt.Errorf("service %s/%s not found: %w", namespace, name, err)
	}
	return nil
}

// ValidateSecretExists validates that a Kubernetes Secret exists
func (r *ReferenceValidator) ValidateSecretExists(ctx context.Context, namespace, name string) error {
	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, secret); err != nil {
		return fmt.Errorf("secret %s/%s not found: %w", namespace, name, err)
	}
	return nil
}

// ValidateBackendExists validates that a Backend exists
func (r *ReferenceValidator) ValidateBackendExists(ctx context.Context, namespace, name string) error {
	backend := &avapigwv1alpha1.Backend{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, backend); err != nil {
		return fmt.Errorf("backend %s/%s not found: %w", namespace, name, err)
	}
	return nil
}

// ValidateTLSConfigExists validates that a TLSConfig exists
func (r *ReferenceValidator) ValidateTLSConfigExists(ctx context.Context, namespace, name string) error {
	tlsConfig := &avapigwv1alpha1.TLSConfig{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, tlsConfig); err != nil {
		return fmt.Errorf("TLSConfig %s/%s not found: %w", namespace, name, err)
	}
	return nil
}

// ValidateParentRefs validates parent references for routes
func (r *ReferenceValidator) ValidateParentRefs(ctx context.Context, parentRefs []avapigwv1alpha1.ParentRef, routeNamespace string) error {
	errs := NewValidationErrors()

	for i, parentRef := range parentRefs {
		namespace := routeNamespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}

		// Check if gateway exists
		if err := r.ValidateGatewayExists(ctx, namespace, parentRef.Name); err != nil {
			errs.Add(fmt.Sprintf("spec.parentRefs[%d]", i), err.Error())
			continue
		}

		// If sectionName is specified, check if the listener exists
		if parentRef.SectionName != nil {
			if err := r.ValidateGatewayListenerExists(ctx, namespace, parentRef.Name, *parentRef.SectionName); err != nil {
				errs.Add(fmt.Sprintf("spec.parentRefs[%d].sectionName", i), err.Error())
			}
		}
	}

	return errs.ToError()
}

// ValidateBackendRefs validates backend references
func (r *ReferenceValidator) ValidateBackendRefs(ctx context.Context, backendRefs []avapigwv1alpha1.BackendRef, routeNamespace string) error {
	errs := NewValidationErrors()

	for i, backendRef := range backendRefs {
		namespace := routeNamespace
		if backendRef.Namespace != nil {
			namespace = *backendRef.Namespace
		}

		kind := refKindService
		if backendRef.Kind != nil {
			kind = *backendRef.Kind
		}

		group := ""
		if backendRef.Group != nil {
			group = *backendRef.Group
		}

		switch {
		case group == "" && kind == refKindService:
			if err := r.ValidateServiceExists(ctx, namespace, backendRef.Name); err != nil {
				errs.Add(fmt.Sprintf("spec.backendRefs[%d]", i), err.Error())
			}
		case group == avapigwv1alpha1.GroupVersion.Group && kind == refKindBackend:
			if err := r.ValidateBackendExists(ctx, namespace, backendRef.Name); err != nil {
				errs.Add(fmt.Sprintf("spec.backendRefs[%d]", i), err.Error())
			}
		default:
			// Unknown backend type - skip validation
		}
	}

	return errs.ToError()
}

// ValidateTargetRef validates a policy target reference
func (r *ReferenceValidator) ValidateTargetRef(ctx context.Context, targetRef *avapigwv1alpha1.TargetRef, policyNamespace string) error {
	namespace := policyNamespace
	if targetRef.Namespace != nil {
		namespace = *targetRef.Namespace
	}

	switch targetRef.Kind {
	case "Gateway":
		return r.ValidateGatewayExists(ctx, namespace, targetRef.Name)
	case "HTTPRoute":
		route := &avapigwv1alpha1.HTTPRoute{}
		if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: targetRef.Name}, route); err != nil {
			return fmt.Errorf("HTTPRoute %s/%s not found: %w", namespace, targetRef.Name, err)
		}
	case "GRPCRoute":
		route := &avapigwv1alpha1.GRPCRoute{}
		if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: targetRef.Name}, route); err != nil {
			return fmt.Errorf("GRPCRoute %s/%s not found: %w", namespace, targetRef.Name, err)
		}
	case "TCPRoute":
		route := &avapigwv1alpha1.TCPRoute{}
		if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: targetRef.Name}, route); err != nil {
			return fmt.Errorf("TCPRoute %s/%s not found: %w", namespace, targetRef.Name, err)
		}
	case "TLSRoute":
		route := &avapigwv1alpha1.TLSRoute{}
		if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: targetRef.Name}, route); err != nil {
			return fmt.Errorf("TLSRoute %s/%s not found: %w", namespace, targetRef.Name, err)
		}
	default:
		return fmt.Errorf("unsupported target kind: %s", targetRef.Kind)
	}

	return nil
}

// ValidateSecretObjectReference validates a SecretObjectReference
func (r *ReferenceValidator) ValidateSecretObjectReference(ctx context.Context, ref *avapigwv1alpha1.SecretObjectReference, defaultNamespace string) error {
	if ref == nil {
		return nil
	}

	namespace := defaultNamespace
	if ref.Namespace != nil {
		namespace = *ref.Namespace
	}

	return r.ValidateSecretExists(ctx, namespace, ref.Name)
}

// ValidateServiceAccountExists validates that a ServiceAccount exists
func (r *ReferenceValidator) ValidateServiceAccountExists(ctx context.Context, namespace, name string) error {
	sa := &corev1.ServiceAccount{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, sa); err != nil {
		return fmt.Errorf("ServiceAccount %s/%s not found: %w", namespace, name, err)
	}
	return nil
}

// CheckGatewayHasAttachedRoutes checks if a Gateway has any attached routes
func (r *ReferenceValidator) CheckGatewayHasAttachedRoutes(ctx context.Context, gatewayNamespace, gatewayName string) (bool, error) {
	// Check HTTPRoutes
	var httpRoutes avapigwv1alpha1.HTTPRouteList
	if err := r.Client.List(ctx, &httpRoutes); err != nil {
		return false, fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}
	for _, route := range httpRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			ns := route.Namespace
			if parentRef.Namespace != nil {
				ns = *parentRef.Namespace
			}
			if ns == gatewayNamespace && parentRef.Name == gatewayName {
				return true, nil
			}
		}
	}

	// Check GRPCRoutes
	var grpcRoutes avapigwv1alpha1.GRPCRouteList
	if err := r.Client.List(ctx, &grpcRoutes); err != nil {
		return false, fmt.Errorf("failed to list GRPCRoutes: %w", err)
	}
	for _, route := range grpcRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			ns := route.Namespace
			if parentRef.Namespace != nil {
				ns = *parentRef.Namespace
			}
			if ns == gatewayNamespace && parentRef.Name == gatewayName {
				return true, nil
			}
		}
	}

	// Check TCPRoutes
	var tcpRoutes avapigwv1alpha1.TCPRouteList
	if err := r.Client.List(ctx, &tcpRoutes); err != nil {
		return false, fmt.Errorf("failed to list TCPRoutes: %w", err)
	}
	for _, route := range tcpRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			ns := route.Namespace
			if parentRef.Namespace != nil {
				ns = *parentRef.Namespace
			}
			if ns == gatewayNamespace && parentRef.Name == gatewayName {
				return true, nil
			}
		}
	}

	// Check TLSRoutes
	var tlsRoutes avapigwv1alpha1.TLSRouteList
	if err := r.Client.List(ctx, &tlsRoutes); err != nil {
		return false, fmt.Errorf("failed to list TLSRoutes: %w", err)
	}
	for _, route := range tlsRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			ns := route.Namespace
			if parentRef.Namespace != nil {
				ns = *parentRef.Namespace
			}
			if ns == gatewayNamespace && parentRef.Name == gatewayName {
				return true, nil
			}
		}
	}

	return false, nil
}

// CheckTLSConfigHasReferences checks if a TLSConfig is referenced by any Gateway
func (r *ReferenceValidator) CheckTLSConfigHasReferences(ctx context.Context, tlsConfigNamespace, tlsConfigName string) (bool, error) {
	var gateways avapigwv1alpha1.GatewayList
	if err := r.Client.List(ctx, &gateways); err != nil {
		return false, fmt.Errorf("failed to list Gateways: %w", err)
	}

	for _, gateway := range gateways.Items {
		for _, listener := range gateway.Spec.Listeners {
			if listener.TLS != nil {
				for _, certRef := range listener.TLS.CertificateRefs {
					ns := gateway.Namespace
					if certRef.Namespace != nil {
						ns = *certRef.Namespace
					}
					if ns == tlsConfigNamespace && certRef.Name == tlsConfigName {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// CheckBackendHasReferences checks if a Backend is referenced by any route
func (r *ReferenceValidator) CheckBackendHasReferences(ctx context.Context, backendNamespace, backendName string) (bool, error) {
	// Check HTTPRoutes
	var httpRoutes avapigwv1alpha1.HTTPRouteList
	if err := r.Client.List(ctx, &httpRoutes); err != nil {
		return false, fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}
	for _, route := range httpRoutes.Items {
		for _, rule := range route.Spec.Rules {
			for _, backendRef := range rule.BackendRefs {
				ns := route.Namespace
				if backendRef.Namespace != nil {
					ns = *backendRef.Namespace
				}
				kind := refKindService
				if backendRef.Kind != nil {
					kind = *backendRef.Kind
				}
				if kind == refKindBackend && ns == backendNamespace && backendRef.Name == backendName {
					return true, nil
				}
			}
		}
	}

	// Similar checks for other route types...
	return false, nil
}
