// Package validator provides validation logic for CRD webhooks.
package validator

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// DuplicateChecker provides methods for checking duplicates across namespaces
type DuplicateChecker struct {
	Client client.Client
}

// NewDuplicateChecker creates a new DuplicateChecker
func NewDuplicateChecker(c client.Client) *DuplicateChecker {
	return &DuplicateChecker{
		Client: c,
	}
}

// CheckGatewayListenerDuplicates checks for duplicate listener port+hostname combinations
func (d *DuplicateChecker) CheckGatewayListenerDuplicates(ctx context.Context, gateway *avapigwv1alpha1.Gateway) error {
	// List all gateways
	var gatewayList avapigwv1alpha1.GatewayList
	if err := d.Client.List(ctx, &gatewayList); err != nil {
		return fmt.Errorf("failed to list gateways: %w", err)
	}

	// Build a map of existing port+hostname combinations
	type listenerKey struct {
		port     int32
		hostname string
	}
	existingListeners := make(map[listenerKey]string) // key -> gateway name

	for _, existingGW := range gatewayList.Items {
		// Skip the current gateway (for updates)
		if existingGW.Namespace == gateway.Namespace && existingGW.Name == gateway.Name {
			continue
		}

		for _, listener := range existingGW.Spec.Listeners {
			hostname := ""
			if listener.Hostname != nil {
				hostname = string(*listener.Hostname)
			}
			key := listenerKey{
				port:     int32(listener.Port),
				hostname: hostname,
			}
			existingListeners[key] = fmt.Sprintf("%s/%s", existingGW.Namespace, existingGW.Name)
		}
	}

	// Check for duplicates in the new gateway
	errs := NewValidationErrors()
	for i, listener := range gateway.Spec.Listeners {
		hostname := ""
		if listener.Hostname != nil {
			hostname = string(*listener.Hostname)
		}
		key := listenerKey{
			port:     int32(listener.Port),
			hostname: hostname,
		}

		if existingGW, exists := existingListeners[key]; exists {
			errs.Add(
				fmt.Sprintf("spec.listeners[%d]", i),
				fmt.Sprintf("listener with port %d and hostname %q already exists in gateway %s",
					listener.Port, hostname, existingGW),
			)
		}
	}

	return errs.ToError()
}

// CheckHTTPRouteDuplicates checks for duplicate hostname+path+method combinations
func (d *DuplicateChecker) CheckHTTPRouteDuplicates(ctx context.Context, route *avapigwv1alpha1.HTTPRoute) error {
	// List all HTTPRoutes
	var routeList avapigwv1alpha1.HTTPRouteList
	if err := d.Client.List(ctx, &routeList); err != nil {
		return fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}

	// Build a map of existing hostname+path+method combinations
	type routeKey struct {
		hostname string
		path     string
		method   string
	}
	existingRoutes := make(map[routeKey]string) // key -> route name

	for _, existingRoute := range routeList.Items {
		// Skip the current route (for updates)
		if existingRoute.Namespace == route.Namespace && existingRoute.Name == route.Name {
			continue
		}

		for _, hostname := range existingRoute.Spec.Hostnames {
			for _, rule := range existingRoute.Spec.Rules {
				for _, match := range rule.Matches {
					path := "/"
					if match.Path != nil && match.Path.Value != nil {
						path = *match.Path.Value
					}
					method := "*"
					if match.Method != nil {
						method = string(*match.Method)
					}
					key := routeKey{
						hostname: string(hostname),
						path:     path,
						method:   method,
					}
					existingRoutes[key] = fmt.Sprintf("%s/%s", existingRoute.Namespace, existingRoute.Name)
				}
			}
		}
	}

	// Check for duplicates in the new route
	errs := NewValidationErrors()
	for _, hostname := range route.Spec.Hostnames {
		for ruleIdx, rule := range route.Spec.Rules {
			for matchIdx, match := range rule.Matches {
				path := "/"
				if match.Path != nil && match.Path.Value != nil {
					path = *match.Path.Value
				}
				method := "*"
				if match.Method != nil {
					method = string(*match.Method)
				}
				key := routeKey{
					hostname: string(hostname),
					path:     path,
					method:   method,
				}

				if existingRoute, exists := existingRoutes[key]; exists {
					errs.Add(
						fmt.Sprintf("spec.rules[%d].matches[%d]", ruleIdx, matchIdx),
						fmt.Sprintf("route with hostname %q, path %q, and method %q already exists in HTTPRoute %s",
							hostname, path, method, existingRoute),
					)
				}
			}
		}
	}

	return errs.ToError()
}

// CheckGRPCRouteDuplicates checks for duplicate hostname+service+method combinations
func (d *DuplicateChecker) CheckGRPCRouteDuplicates(ctx context.Context, route *avapigwv1alpha1.GRPCRoute) error {
	// List all GRPCRoutes
	var routeList avapigwv1alpha1.GRPCRouteList
	if err := d.Client.List(ctx, &routeList); err != nil {
		return fmt.Errorf("failed to list GRPCRoutes: %w", err)
	}

	// Build a map of existing hostname+service+method combinations
	type routeKey struct {
		hostname string
		service  string
		method   string
	}
	existingRoutes := make(map[routeKey]string) // key -> route name

	for _, existingRoute := range routeList.Items {
		// Skip the current route (for updates)
		if existingRoute.Namespace == route.Namespace && existingRoute.Name == route.Name {
			continue
		}

		for _, hostname := range existingRoute.Spec.Hostnames {
			for _, rule := range existingRoute.Spec.Rules {
				for _, match := range rule.Matches {
					service := "*"
					method := "*"
					if match.Method != nil {
						if match.Method.Service != nil {
							service = *match.Method.Service
						}
						if match.Method.Method != nil {
							method = *match.Method.Method
						}
					}
					key := routeKey{
						hostname: string(hostname),
						service:  service,
						method:   method,
					}
					existingRoutes[key] = fmt.Sprintf("%s/%s", existingRoute.Namespace, existingRoute.Name)
				}
			}
		}
	}

	// Check for duplicates in the new route
	errs := NewValidationErrors()
	for _, hostname := range route.Spec.Hostnames {
		for ruleIdx, rule := range route.Spec.Rules {
			for matchIdx, match := range rule.Matches {
				service := "*"
				method := "*"
				if match.Method != nil {
					if match.Method.Service != nil {
						service = *match.Method.Service
					}
					if match.Method.Method != nil {
						method = *match.Method.Method
					}
				}
				key := routeKey{
					hostname: string(hostname),
					service:  service,
					method:   method,
				}

				if existingRoute, exists := existingRoutes[key]; exists {
					errs.Add(
						fmt.Sprintf("spec.rules[%d].matches[%d]", ruleIdx, matchIdx),
						fmt.Sprintf("route with hostname %q, service %q, and method %q already exists in GRPCRoute %s",
							hostname, service, method, existingRoute),
					)
				}
			}
		}
	}

	return errs.ToError()
}

// CheckTCPRoutePortConflicts checks for port conflicts in TCPRoutes
func (d *DuplicateChecker) CheckTCPRoutePortConflicts(ctx context.Context, route *avapigwv1alpha1.TCPRoute) error {
	// TCPRoutes are bound to specific gateway listeners by port
	// Check if any other TCPRoute is bound to the same listener
	var routeList avapigwv1alpha1.TCPRouteList
	if err := d.Client.List(ctx, &routeList); err != nil {
		return fmt.Errorf("failed to list TCPRoutes: %w", err)
	}

	// Build a map of existing parent refs
	type parentKey struct {
		namespace   string
		name        string
		sectionName string
		port        int32
	}
	existingParents := make(map[parentKey]string) // key -> route name

	for _, existingRoute := range routeList.Items {
		// Skip the current route (for updates)
		if existingRoute.Namespace == route.Namespace && existingRoute.Name == route.Name {
			continue
		}

		for _, parentRef := range existingRoute.Spec.ParentRefs {
			ns := existingRoute.Namespace
			if parentRef.Namespace != nil {
				ns = *parentRef.Namespace
			}
			sectionName := ""
			if parentRef.SectionName != nil {
				sectionName = *parentRef.SectionName
			}
			port := int32(0)
			if parentRef.Port != nil {
				port = *parentRef.Port
			}
			key := parentKey{
				namespace:   ns,
				name:        parentRef.Name,
				sectionName: sectionName,
				port:        port,
			}
			existingParents[key] = fmt.Sprintf("%s/%s", existingRoute.Namespace, existingRoute.Name)
		}
	}

	// Check for conflicts in the new route
	errs := NewValidationErrors()
	for i, parentRef := range route.Spec.ParentRefs {
		ns := route.Namespace
		if parentRef.Namespace != nil {
			ns = *parentRef.Namespace
		}
		sectionName := ""
		if parentRef.SectionName != nil {
			sectionName = *parentRef.SectionName
		}
		port := int32(0)
		if parentRef.Port != nil {
			port = *parentRef.Port
		}
		key := parentKey{
			namespace:   ns,
			name:        parentRef.Name,
			sectionName: sectionName,
			port:        port,
		}

		if existingRoute, exists := existingParents[key]; exists {
			errs.Add(
				fmt.Sprintf("spec.parentRefs[%d]", i),
				fmt.Sprintf("TCPRoute already bound to gateway %s/%s listener %s by route %s",
					ns, parentRef.Name, sectionName, existingRoute),
			)
		}
	}

	return errs.ToError()
}

// CheckTLSRouteHostnameDuplicates checks for duplicate hostname configurations
func (d *DuplicateChecker) CheckTLSRouteHostnameDuplicates(ctx context.Context, route *avapigwv1alpha1.TLSRoute) error {
	// List all TLSRoutes
	var routeList avapigwv1alpha1.TLSRouteList
	if err := d.Client.List(ctx, &routeList); err != nil {
		return fmt.Errorf("failed to list TLSRoutes: %w", err)
	}

	// Build a map of existing hostnames per parent
	type routeKey struct {
		parentNS   string
		parentName string
		hostname   string
	}
	existingRoutes := make(map[routeKey]string) // key -> route name

	for _, existingRoute := range routeList.Items {
		// Skip the current route (for updates)
		if existingRoute.Namespace == route.Namespace && existingRoute.Name == route.Name {
			continue
		}

		for _, parentRef := range existingRoute.Spec.ParentRefs {
			parentNS := existingRoute.Namespace
			if parentRef.Namespace != nil {
				parentNS = *parentRef.Namespace
			}
			for _, hostname := range existingRoute.Spec.Hostnames {
				key := routeKey{
					parentNS:   parentNS,
					parentName: parentRef.Name,
					hostname:   string(hostname),
				}
				existingRoutes[key] = fmt.Sprintf("%s/%s", existingRoute.Namespace, existingRoute.Name)
			}
		}
	}

	// Check for duplicates in the new route
	errs := NewValidationErrors()
	for _, parentRef := range route.Spec.ParentRefs {
		parentNS := route.Namespace
		if parentRef.Namespace != nil {
			parentNS = *parentRef.Namespace
		}
		for i, hostname := range route.Spec.Hostnames {
			key := routeKey{
				parentNS:   parentNS,
				parentName: parentRef.Name,
				hostname:   string(hostname),
			}

			if existingRoute, exists := existingRoutes[key]; exists {
				errs.Add(
					fmt.Sprintf("spec.hostnames[%d]", i),
					fmt.Sprintf("TLSRoute with hostname %q already exists for gateway %s/%s in route %s",
						hostname, parentNS, parentRef.Name, existingRoute),
				)
			}
		}
	}

	return errs.ToError()
}

// CheckPolicyTargetDuplicates checks for duplicate policy targetRefs
func (d *DuplicateChecker) CheckPolicyTargetDuplicates(ctx context.Context, targetRef *avapigwv1alpha1.TargetRef, policyNamespace, policyName, policyKind string) error {
	targetNS := policyNamespace
	if targetRef.Namespace != nil {
		targetNS = *targetRef.Namespace
	}

	switch policyKind {
	case "RateLimitPolicy":
		var policyList avapigwv1alpha1.RateLimitPolicyList
		if err := d.Client.List(ctx, &policyList); err != nil {
			return fmt.Errorf("failed to list RateLimitPolicies: %w", err)
		}

		for _, policy := range policyList.Items {
			if policy.Namespace == policyNamespace && policy.Name == policyName {
				continue
			}

			existingTargetNS := policy.Namespace
			if policy.Spec.TargetRef.Namespace != nil {
				existingTargetNS = *policy.Spec.TargetRef.Namespace
			}

			if policy.Spec.TargetRef.Group == targetRef.Group &&
				policy.Spec.TargetRef.Kind == targetRef.Kind &&
				policy.Spec.TargetRef.Name == targetRef.Name &&
				existingTargetNS == targetNS {
				return NewValidationError("spec.targetRef",
					fmt.Sprintf("RateLimitPolicy %s/%s already targets %s/%s %s",
						policy.Namespace, policy.Name, targetNS, targetRef.Kind, targetRef.Name))
			}
		}

	case "AuthPolicy":
		var policyList avapigwv1alpha1.AuthPolicyList
		if err := d.Client.List(ctx, &policyList); err != nil {
			return fmt.Errorf("failed to list AuthPolicies: %w", err)
		}

		for _, policy := range policyList.Items {
			if policy.Namespace == policyNamespace && policy.Name == policyName {
				continue
			}

			existingTargetNS := policy.Namespace
			if policy.Spec.TargetRef.Namespace != nil {
				existingTargetNS = *policy.Spec.TargetRef.Namespace
			}

			if policy.Spec.TargetRef.Group == targetRef.Group &&
				policy.Spec.TargetRef.Kind == targetRef.Kind &&
				policy.Spec.TargetRef.Name == targetRef.Name &&
				existingTargetNS == targetNS {
				return NewValidationError("spec.targetRef",
					fmt.Sprintf("AuthPolicy %s/%s already targets %s/%s %s",
						policy.Namespace, policy.Name, targetNS, targetRef.Kind, targetRef.Name))
			}
		}
	}

	return nil
}
