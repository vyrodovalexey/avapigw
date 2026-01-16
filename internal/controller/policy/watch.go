// Package policy provides shared utilities for policy controllers.
package policy

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// PolicyList is an interface for policy list types that can be iterated.
type PolicyList[T PolicyWithTargetRef] interface {
	client.ObjectList
	// GetPolicies returns the list of policies.
	GetPolicies() []T
}

// PolicyWatchHandler provides watch handler utilities for policy controllers.
// It uses generics to work with different policy types (AuthPolicy, RateLimitPolicy).
type PolicyWatchHandler[T PolicyWithTargetRef, L PolicyList[T]] struct {
	client     client.Client
	listObject L
}

// NewPolicyWatchHandler creates a new PolicyWatchHandler.
// The listObject parameter should be a pointer to an empty list object (e.g., &AuthPolicyList{}).
func NewPolicyWatchHandler[T PolicyWithTargetRef, L PolicyList[T]](
	c client.Client,
	listObject L,
) *PolicyWatchHandler[T, L] {
	return &PolicyWatchHandler[T, L]{
		client:     c,
		listObject: listObject,
	}
}

// FindPoliciesForTarget finds policies that target a specific resource.
// It lists all policies and filters those that match the target kind, namespace, and name.
// Returns a list of reconcile requests for matching policies.
func (h *PolicyWatchHandler[T, L]) FindPoliciesForTarget(
	ctx context.Context,
	kind, namespace, name string,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// List all policies
	if err := h.client.List(ctx, h.listObject); err != nil {
		logger.Error(err, "Failed to list policies for target",
			"targetKind", kind,
			"targetNamespace", namespace,
			"targetName", name,
		)
		return nil
	}

	// Filter policies that match the target
	var requests []reconcile.Request
	for _, policy := range h.listObject.GetPolicies() {
		if MatchesTarget(policy, kind, namespace, name) {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKey{
					Namespace: policy.GetNamespace(),
					Name:      policy.GetName(),
				},
			})
		}
	}

	if len(requests) > 0 {
		logger.V(1).Info("Found policies targeting resource",
			"targetKind", kind,
			"targetNamespace", namespace,
			"targetName", name,
			"policyCount", len(requests),
		)
	}

	return requests
}

// FindPoliciesForGateway finds policies that target a specific Gateway.
// This is a convenience method that calls FindPoliciesForTarget with kind="Gateway".
func (h *PolicyWatchHandler[T, L]) FindPoliciesForGateway(
	ctx context.Context,
	namespace, name string,
) []reconcile.Request {
	return h.FindPoliciesForTarget(ctx, TargetKindGateway, namespace, name)
}

// FindPoliciesForHTTPRoute finds policies that target a specific HTTPRoute.
// This is a convenience method that calls FindPoliciesForTarget with kind="HTTPRoute".
func (h *PolicyWatchHandler[T, L]) FindPoliciesForHTTPRoute(
	ctx context.Context,
	namespace, name string,
) []reconcile.Request {
	return h.FindPoliciesForTarget(ctx, TargetKindHTTPRoute, namespace, name)
}

// FindPoliciesForGRPCRoute finds policies that target a specific GRPCRoute.
// This is a convenience method that calls FindPoliciesForTarget with kind="GRPCRoute".
func (h *PolicyWatchHandler[T, L]) FindPoliciesForGRPCRoute(
	ctx context.Context,
	namespace, name string,
) []reconcile.Request {
	return h.FindPoliciesForTarget(ctx, TargetKindGRPCRoute, namespace, name)
}
