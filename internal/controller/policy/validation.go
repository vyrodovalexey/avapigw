// Package policy provides shared utilities for policy controllers.
package policy

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Supported target kinds for policy attachment.
const (
	TargetKindGateway   = "Gateway"
	TargetKindHTTPRoute = "HTTPRoute"
	TargetKindGRPCRoute = "GRPCRoute"
)

// PolicyWithTargetRef defines interface for policies with target references.
// This allows generic handling of different policy types.
type PolicyWithTargetRef interface {
	client.Object
	// GetTargetRef returns the target reference for the policy.
	GetTargetRef() avapigwv1alpha1.TargetRef
}

// TargetRefValidator validates target references for policies.
// It checks if the target resource (Gateway, HTTPRoute, GRPCRoute) exists.
type TargetRefValidator struct {
	client client.Client
}

// NewTargetRefValidator creates a new TargetRefValidator.
func NewTargetRefValidator(c client.Client) *TargetRefValidator {
	return &TargetRefValidator{
		client: c,
	}
}

// ValidateTargetRef validates the target reference for a policy.
// It checks:
//   - If the target kind is supported (Gateway, HTTPRoute, GRPCRoute)
//   - If the target resource exists in the specified namespace
//
// Returns an error if validation fails.
func (v *TargetRefValidator) ValidateTargetRef(ctx context.Context, policy PolicyWithTargetRef) error {
	logger := log.FromContext(ctx)
	targetRef := policy.GetTargetRef()

	// Determine the target namespace
	namespace := policy.GetNamespace()
	if targetRef.Namespace != nil {
		namespace = *targetRef.Namespace
	}

	logger.V(1).Info("Validating target reference",
		"policy", policy.GetName(),
		"policyNamespace", policy.GetNamespace(),
		"targetKind", targetRef.Kind,
		"targetName", targetRef.Name,
		"targetNamespace", namespace,
	)

	// Validate based on target kind
	switch targetRef.Kind {
	case TargetKindGateway:
		return v.validateGatewayTarget(ctx, namespace, targetRef.Name)
	case TargetKindHTTPRoute:
		return v.validateHTTPRouteTarget(ctx, namespace, targetRef.Name)
	case TargetKindGRPCRoute:
		return v.validateGRPCRouteTarget(ctx, namespace, targetRef.Name)
	default:
		return fmt.Errorf("unsupported target kind: %s", targetRef.Kind)
	}
}

// validateGatewayTarget validates that a Gateway target exists.
func (v *TargetRefValidator) validateGatewayTarget(ctx context.Context, namespace, name string) error {
	gateway := &avapigwv1alpha1.Gateway{}
	if err := v.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, gateway); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("target Gateway %s/%s not found", namespace, name)
		}
		return fmt.Errorf("failed to get target Gateway %s/%s: %w", namespace, name, err)
	}
	return nil
}

// validateHTTPRouteTarget validates that an HTTPRoute target exists.
func (v *TargetRefValidator) validateHTTPRouteTarget(ctx context.Context, namespace, name string) error {
	route := &avapigwv1alpha1.HTTPRoute{}
	if err := v.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, route); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("target HTTPRoute %s/%s not found", namespace, name)
		}
		return fmt.Errorf("failed to get target HTTPRoute %s/%s: %w", namespace, name, err)
	}
	return nil
}

// validateGRPCRouteTarget validates that a GRPCRoute target exists.
func (v *TargetRefValidator) validateGRPCRouteTarget(ctx context.Context, namespace, name string) error {
	route := &avapigwv1alpha1.GRPCRoute{}
	if err := v.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, route); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("target GRPCRoute %s/%s not found", namespace, name)
		}
		return fmt.Errorf("failed to get target GRPCRoute %s/%s: %w", namespace, name, err)
	}
	return nil
}

// GetTargetNamespace returns the effective target namespace for a policy.
// If the target reference specifies a namespace, it returns that namespace.
// Otherwise, it returns the policy's namespace.
func GetTargetNamespace(policy PolicyWithTargetRef) string {
	targetRef := policy.GetTargetRef()
	if targetRef.Namespace != nil {
		return *targetRef.Namespace
	}
	return policy.GetNamespace()
}

// MatchesTarget checks if a policy targets a specific resource.
// It compares the target kind, namespace, and name.
func MatchesTarget(policy PolicyWithTargetRef, kind, namespace, name string) bool {
	targetRef := policy.GetTargetRef()

	// Check kind match
	if targetRef.Kind != kind {
		return false
	}

	// Check name match
	if targetRef.Name != name {
		return false
	}

	// Check namespace match
	targetNamespace := GetTargetNamespace(policy)
	return targetNamespace == namespace
}
