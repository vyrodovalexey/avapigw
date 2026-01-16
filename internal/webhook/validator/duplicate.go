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

// httpRouteKey represents a unique key for HTTP route matching
type httpRouteKey struct {
	hostname string
	path     string
	method   string
}

// buildExistingHTTPRouteKeys builds a map of existing HTTP route keys from the route list
func (d *DuplicateChecker) buildExistingHTTPRouteKeys(
	routeList *avapigwv1alpha1.HTTPRouteList,
	currentRoute *avapigwv1alpha1.HTTPRoute,
) map[httpRouteKey]string {
	existingRoutes := make(map[httpRouteKey]string)

	for _, existingRoute := range routeList.Items {
		// Skip the current route (for updates)
		if existingRoute.Namespace == currentRoute.Namespace && existingRoute.Name == currentRoute.Name {
			continue
		}

		for _, hostname := range existingRoute.Spec.Hostnames {
			for _, rule := range existingRoute.Spec.Rules {
				for _, match := range rule.Matches {
					key := d.extractHTTPRouteKey(string(hostname), &match)
					existingRoutes[key] = fmt.Sprintf("%s/%s", existingRoute.Namespace, existingRoute.Name)
				}
			}
		}
	}

	return existingRoutes
}

// extractHTTPRouteKey extracts the route key from a match
func (d *DuplicateChecker) extractHTTPRouteKey(hostname string, match *avapigwv1alpha1.HTTPRouteMatch) httpRouteKey {
	path := "/"
	if match.Path != nil && match.Path.Value != nil {
		path = *match.Path.Value
	}
	method := "*"
	if match.Method != nil {
		method = string(*match.Method)
	}
	return httpRouteKey{
		hostname: hostname,
		path:     path,
		method:   method,
	}
}

// CheckHTTPRouteDuplicates checks for duplicate hostname+path+method combinations
func (d *DuplicateChecker) CheckHTTPRouteDuplicates(ctx context.Context, route *avapigwv1alpha1.HTTPRoute) error {
	var routeList avapigwv1alpha1.HTTPRouteList
	if err := d.Client.List(ctx, &routeList); err != nil {
		return fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}

	existingRoutes := d.buildExistingHTTPRouteKeys(&routeList, route)

	errs := NewValidationErrors()
	for _, hostname := range route.Spec.Hostnames {
		for ruleIdx, rule := range route.Spec.Rules {
			for matchIdx, match := range rule.Matches {
				key := d.extractHTTPRouteKey(string(hostname), &match)

				if existingRoute, exists := existingRoutes[key]; exists {
					errs.Add(
						fmt.Sprintf("spec.rules[%d].matches[%d]", ruleIdx, matchIdx),
						fmt.Sprintf("route with hostname %q, path %q, and method %q already exists in HTTPRoute %s",
							hostname, key.path, key.method, existingRoute),
					)
				}
			}
		}
	}

	return errs.ToError()
}

// grpcRouteKey represents a unique key for GRPC route matching
type grpcRouteKey struct {
	hostname string
	service  string
	method   string
}

// buildExistingGRPCRouteKeys builds a map of existing GRPC route keys from the route list
func (d *DuplicateChecker) buildExistingGRPCRouteKeys(
	routeList *avapigwv1alpha1.GRPCRouteList,
	currentRoute *avapigwv1alpha1.GRPCRoute,
) map[grpcRouteKey]string {
	existingRoutes := make(map[grpcRouteKey]string)

	for _, existingRoute := range routeList.Items {
		// Skip the current route (for updates)
		if existingRoute.Namespace == currentRoute.Namespace && existingRoute.Name == currentRoute.Name {
			continue
		}

		for _, hostname := range existingRoute.Spec.Hostnames {
			for _, rule := range existingRoute.Spec.Rules {
				for _, match := range rule.Matches {
					key := d.extractGRPCRouteKey(string(hostname), &match)
					existingRoutes[key] = fmt.Sprintf("%s/%s", existingRoute.Namespace, existingRoute.Name)
				}
			}
		}
	}

	return existingRoutes
}

// extractGRPCRouteKey extracts the route key from a GRPC match
func (d *DuplicateChecker) extractGRPCRouteKey(hostname string, match *avapigwv1alpha1.GRPCRouteMatch) grpcRouteKey {
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
	return grpcRouteKey{
		hostname: hostname,
		service:  service,
		method:   method,
	}
}

// CheckGRPCRouteDuplicates checks for duplicate hostname+service+method combinations
func (d *DuplicateChecker) CheckGRPCRouteDuplicates(ctx context.Context, route *avapigwv1alpha1.GRPCRoute) error {
	var routeList avapigwv1alpha1.GRPCRouteList
	if err := d.Client.List(ctx, &routeList); err != nil {
		return fmt.Errorf("failed to list GRPCRoutes: %w", err)
	}

	existingRoutes := d.buildExistingGRPCRouteKeys(&routeList, route)

	errs := NewValidationErrors()
	for _, hostname := range route.Spec.Hostnames {
		for ruleIdx, rule := range route.Spec.Rules {
			for matchIdx, match := range rule.Matches {
				key := d.extractGRPCRouteKey(string(hostname), &match)

				if existingRoute, exists := existingRoutes[key]; exists {
					errs.Add(
						fmt.Sprintf("spec.rules[%d].matches[%d]", ruleIdx, matchIdx),
						fmt.Sprintf("route with hostname %q, service %q, and method %q already exists in GRPCRoute %s",
							hostname, key.service, key.method, existingRoute),
					)
				}
			}
		}
	}

	return errs.ToError()
}

// tcpParentKey represents a unique key for TCP route parent reference
type tcpParentKey struct {
	namespace   string
	name        string
	sectionName string
	port        int32
}

// buildExistingTCPParentKeys builds a map of existing TCP parent keys from the route list
func (d *DuplicateChecker) buildExistingTCPParentKeys(
	routeList *avapigwv1alpha1.TCPRouteList,
	currentRoute *avapigwv1alpha1.TCPRoute,
) map[tcpParentKey]string {
	existingParents := make(map[tcpParentKey]string)

	for _, existingRoute := range routeList.Items {
		// Skip the current route (for updates)
		if existingRoute.Namespace == currentRoute.Namespace && existingRoute.Name == currentRoute.Name {
			continue
		}

		for _, parentRef := range existingRoute.Spec.ParentRefs {
			key := d.extractTCPParentKey(existingRoute.Namespace, &parentRef)
			existingParents[key] = fmt.Sprintf("%s/%s", existingRoute.Namespace, existingRoute.Name)
		}
	}

	return existingParents
}

// extractTCPParentKey extracts the parent key from a parent reference
func (d *DuplicateChecker) extractTCPParentKey(
	defaultNamespace string,
	parentRef *avapigwv1alpha1.ParentRef,
) tcpParentKey {
	ns := defaultNamespace
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
	return tcpParentKey{
		namespace:   ns,
		name:        parentRef.Name,
		sectionName: sectionName,
		port:        port,
	}
}

// CheckTCPRoutePortConflicts checks for port conflicts in TCPRoutes
func (d *DuplicateChecker) CheckTCPRoutePortConflicts(ctx context.Context, route *avapigwv1alpha1.TCPRoute) error {
	var routeList avapigwv1alpha1.TCPRouteList
	if err := d.Client.List(ctx, &routeList); err != nil {
		return fmt.Errorf("failed to list TCPRoutes: %w", err)
	}

	existingParents := d.buildExistingTCPParentKeys(&routeList, route)

	errs := NewValidationErrors()
	for i, parentRef := range route.Spec.ParentRefs {
		key := d.extractTCPParentKey(route.Namespace, &parentRef)

		if existingRoute, exists := existingParents[key]; exists {
			errs.Add(
				fmt.Sprintf("spec.parentRefs[%d]", i),
				fmt.Sprintf("TCPRoute already bound to gateway %s/%s listener %s by route %s",
					key.namespace, parentRef.Name, key.sectionName, existingRoute),
			)
		}
	}

	return errs.ToError()
}

// tlsRouteKey represents a unique key for TLS route hostname matching
type tlsRouteKey struct {
	parentNS   string
	parentName string
	hostname   string
}

// buildExistingTLSRouteKeys builds a map of existing TLS route keys from the route list
func (d *DuplicateChecker) buildExistingTLSRouteKeys(
	routeList *avapigwv1alpha1.TLSRouteList,
	currentRoute *avapigwv1alpha1.TLSRoute,
) map[tlsRouteKey]string {
	existingRoutes := make(map[tlsRouteKey]string)

	for _, existingRoute := range routeList.Items {
		// Skip the current route (for updates)
		if existingRoute.Namespace == currentRoute.Namespace && existingRoute.Name == currentRoute.Name {
			continue
		}

		for _, parentRef := range existingRoute.Spec.ParentRefs {
			parentNS := existingRoute.Namespace
			if parentRef.Namespace != nil {
				parentNS = *parentRef.Namespace
			}
			for _, hostname := range existingRoute.Spec.Hostnames {
				key := tlsRouteKey{
					parentNS:   parentNS,
					parentName: parentRef.Name,
					hostname:   string(hostname),
				}
				existingRoutes[key] = fmt.Sprintf("%s/%s", existingRoute.Namespace, existingRoute.Name)
			}
		}
	}

	return existingRoutes
}

// CheckTLSRouteHostnameDuplicates checks for duplicate hostname configurations
func (d *DuplicateChecker) CheckTLSRouteHostnameDuplicates(ctx context.Context, route *avapigwv1alpha1.TLSRoute) error {
	var routeList avapigwv1alpha1.TLSRouteList
	if err := d.Client.List(ctx, &routeList); err != nil {
		return fmt.Errorf("failed to list TLSRoutes: %w", err)
	}

	existingRoutes := d.buildExistingTLSRouteKeys(&routeList, route)

	errs := NewValidationErrors()
	for _, parentRef := range route.Spec.ParentRefs {
		parentNS := route.Namespace
		if parentRef.Namespace != nil {
			parentNS = *parentRef.Namespace
		}
		for i, hostname := range route.Spec.Hostnames {
			key := tlsRouteKey{
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
func (d *DuplicateChecker) CheckPolicyTargetDuplicates(
	ctx context.Context,
	targetRef *avapigwv1alpha1.TargetRef,
	policyNamespace, policyName, policyKind string,
) error {
	targetNS := policyNamespace
	if targetRef.Namespace != nil {
		targetNS = *targetRef.Namespace
	}

	switch policyKind {
	case "RateLimitPolicy":
		return d.checkRateLimitPolicyDuplicates(ctx, targetRef, policyNamespace, policyName, targetNS)
	case "AuthPolicy":
		return d.checkAuthPolicyDuplicates(ctx, targetRef, policyNamespace, policyName, targetNS)
	}

	return nil
}

// checkRateLimitPolicyDuplicates checks for duplicate RateLimitPolicy targetRefs
func (d *DuplicateChecker) checkRateLimitPolicyDuplicates(
	ctx context.Context,
	targetRef *avapigwv1alpha1.TargetRef,
	policyNamespace, policyName, targetNS string,
) error {
	var policyList avapigwv1alpha1.RateLimitPolicyList
	if err := d.Client.List(ctx, &policyList); err != nil {
		return fmt.Errorf("failed to list RateLimitPolicies: %w", err)
	}

	for _, policy := range policyList.Items {
		if policy.Namespace == policyNamespace && policy.Name == policyName {
			continue
		}

		if d.targetRefMatches(&policy.Spec.TargetRef, targetRef, policy.Namespace, targetNS) {
			return NewValidationError("spec.targetRef",
				fmt.Sprintf("RateLimitPolicy %s/%s already targets %s/%s %s",
					policy.Namespace, policy.Name, targetNS, targetRef.Kind, targetRef.Name))
		}
	}

	return nil
}

// checkAuthPolicyDuplicates checks for duplicate AuthPolicy targetRefs
func (d *DuplicateChecker) checkAuthPolicyDuplicates(
	ctx context.Context,
	targetRef *avapigwv1alpha1.TargetRef,
	policyNamespace, policyName, targetNS string,
) error {
	var policyList avapigwv1alpha1.AuthPolicyList
	if err := d.Client.List(ctx, &policyList); err != nil {
		return fmt.Errorf("failed to list AuthPolicies: %w", err)
	}

	for _, policy := range policyList.Items {
		if policy.Namespace == policyNamespace && policy.Name == policyName {
			continue
		}

		if d.targetRefMatches(&policy.Spec.TargetRef, targetRef, policy.Namespace, targetNS) {
			return NewValidationError("spec.targetRef",
				fmt.Sprintf("AuthPolicy %s/%s already targets %s/%s %s",
					policy.Namespace, policy.Name, targetNS, targetRef.Kind, targetRef.Name))
		}
	}

	return nil
}

// targetRefMatches checks if an existing policy's targetRef matches the new targetRef
func (d *DuplicateChecker) targetRefMatches(
	existingRef, newRef *avapigwv1alpha1.TargetRef,
	existingPolicyNS, targetNS string,
) bool {
	existingTargetNS := existingPolicyNS
	if existingRef.Namespace != nil {
		existingTargetNS = *existingRef.Namespace
	}

	return existingRef.Group == newRef.Group &&
		existingRef.Kind == newRef.Kind &&
		existingRef.Name == newRef.Name &&
		existingTargetNS == targetNS
}
