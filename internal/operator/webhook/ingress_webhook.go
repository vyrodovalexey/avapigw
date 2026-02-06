// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ingressClassFieldName is the IngressClass name this webhook validates.
const ingressClassFieldName = "avapigw"

// Annotation constants for gRPC protocol detection.
const (
	annotationProtocol = "avapigw.io/protocol"
	protocolGRPC       = "grpc"
)

// IngressValidator validates Kubernetes Ingress resources assigned to the avapigw IngressClass.
// It ensures host/path combinations are valid, TLS configuration references valid secrets,
// backend service references are valid, and there are no conflicts with existing APIRoute or GRPCRoute CRDs.
type IngressValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
	IngressClassName string
}

// SetupIngressWebhook sets up the Ingress validating webhook with the manager.
func SetupIngressWebhook(mgr ctrl.Manager, ingressClassName string) error {
	if ingressClassName == "" {
		ingressClassName = ingressClassFieldName
	}

	validator := &IngressValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateChecker(mgr.GetClient()),
		IngressClassName: ingressClassName,
	}
	return ctrl.NewWebhookManagedBy(mgr, &networkingv1.Ingress{}).
		WithValidator(validator).
		Complete()
}

// ValidateCreate implements admission.CustomValidator.
func (v *IngressValidator) ValidateCreate(
	ctx context.Context,
	obj *networkingv1.Ingress,
) (admission.Warnings, error) {
	if !v.matchesIngressClass(obj) {
		// Not our IngressClass, skip validation
		return nil, nil
	}

	warnings, err := v.validate(obj)
	if err != nil {
		return warnings, err
	}

	// Check for conflicts with existing CRDs based on protocol
	if v.DuplicateChecker != nil {
		if v.isGRPCIngress(obj) {
			// Check for conflicts with existing GRPCRoute CRDs
			if conflictErr := v.checkGRPCRouteConflicts(ctx, obj); conflictErr != nil {
				return warnings, conflictErr
			}
		} else {
			// Check for conflicts with existing APIRoute CRDs
			if conflictErr := v.checkAPIRouteConflicts(ctx, obj); conflictErr != nil {
				return warnings, conflictErr
			}
		}
	}

	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (v *IngressValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj *networkingv1.Ingress,
) (admission.Warnings, error) {
	if !v.matchesIngressClass(newObj) {
		// Not our IngressClass, skip validation
		return nil, nil
	}

	warnings, err := v.validate(newObj)
	if err != nil {
		return warnings, err
	}

	// Check for conflicts with existing CRDs based on protocol
	if v.DuplicateChecker != nil {
		if v.isGRPCIngress(newObj) {
			// Check for conflicts with existing GRPCRoute CRDs
			if conflictErr := v.checkGRPCRouteConflicts(ctx, newObj); conflictErr != nil {
				return warnings, conflictErr
			}
		} else {
			// Check for conflicts with existing APIRoute CRDs
			if conflictErr := v.checkAPIRouteConflicts(ctx, newObj); conflictErr != nil {
				return warnings, conflictErr
			}
		}
	}

	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
func (v *IngressValidator) ValidateDelete(
	_ context.Context,
	_ *networkingv1.Ingress,
) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// matchesIngressClass checks whether the Ingress is assigned to our IngressClass.
func (v *IngressValidator) matchesIngressClass(ingress *networkingv1.Ingress) bool {
	// Check spec.ingressClassName first (preferred)
	if ingress.Spec.IngressClassName != nil {
		return *ingress.Spec.IngressClassName == v.IngressClassName
	}

	// Fall back to legacy annotation
	if annotations := ingress.Annotations; annotations != nil {
		if className, ok := annotations["kubernetes.io/ingress.class"]; ok {
			return className == v.IngressClassName
		}
	}

	return false
}

// validate performs validation on the Ingress spec.
//
//nolint:gocognit,gocyclo // Validation requires checking rules, hosts, paths, TLS, and backends
func (v *IngressValidator) validate(ingress *networkingv1.Ingress) (admission.Warnings, error) {
	var warnings admission.Warnings
	var errs []string

	// Validate rules
	if err := v.validateRules(ingress.Spec.Rules); err != nil {
		errs = append(errs, err.Error())
	}

	// Validate TLS configuration
	if len(ingress.Spec.TLS) > 0 {
		if err := v.validateTLS(ingress.Spec.TLS, ingress.Spec.Rules); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate default backend if specified
	if ingress.Spec.DefaultBackend != nil {
		if err := v.validateIngressBackend(ingress.Spec.DefaultBackend, "defaultBackend"); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Check for duplicate host/path combinations within the same Ingress
	if err := v.checkDuplicateHostPaths(ingress.Spec.Rules); err != nil {
		errs = append(errs, err.Error())
	}

	// Warn if no rules and no default backend
	if len(ingress.Spec.Rules) == 0 && ingress.Spec.DefaultBackend == nil {
		warnings = append(warnings, "Ingress has no rules and no default backend")
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

// validateRules validates Ingress rules.
func (v *IngressValidator) validateRules(rules []networkingv1.IngressRule) error {
	var errs []string

	for i, rule := range rules {
		// Validate host if specified
		if rule.Host != "" {
			if err := validateIngressHost(rule.Host); err != nil {
				errs = append(errs, fmt.Sprintf("rules[%d].host: %v", i, err))
			}
		}

		// Validate HTTP paths
		if rule.HTTP == nil {
			continue
		}

		if len(rule.HTTP.Paths) == 0 {
			errs = append(errs, fmt.Sprintf("rules[%d]: at least one path is required when HTTP is specified", i))
			continue
		}

		for j, path := range rule.HTTP.Paths {
			if err := v.validateIngressPath(&path, fmt.Sprintf("rules[%d].http.paths[%d]", i, j)); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	return nil
}

// validateIngressPath validates a single Ingress path.
func (v *IngressValidator) validateIngressPath(
	path *networkingv1.HTTPIngressPath,
	fieldPath string,
) error {
	var errs []string

	// Validate path value
	if path.Path == "" {
		errs = append(errs, fmt.Sprintf("%s.path is required", fieldPath))
	} else if !strings.HasPrefix(path.Path, "/") {
		errs = append(errs, fmt.Sprintf("%s.path must start with '/'", fieldPath))
	}

	// Validate path type
	if path.PathType != nil {
		validTypes := map[networkingv1.PathType]bool{
			networkingv1.PathTypePrefix:                 true,
			networkingv1.PathTypeExact:                  true,
			networkingv1.PathTypeImplementationSpecific: true,
		}
		if !validTypes[*path.PathType] {
			errs = append(errs, fmt.Sprintf(
				"%s.pathType must be Prefix, Exact, or ImplementationSpecific",
				fieldPath,
			))
		}
	}

	// Validate backend
	if err := v.validateIngressBackend(&path.Backend, fieldPath+".backend"); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	return nil
}

// validateIngressBackend validates an Ingress backend reference.
func (v *IngressValidator) validateIngressBackend(
	backend *networkingv1.IngressBackend,
	fieldPath string,
) error {
	if backend.Service == nil && backend.Resource == nil {
		return fmt.Errorf("%s: either service or resource must be specified", fieldPath)
	}

	if backend.Service != nil {
		if backend.Service.Name == "" {
			return fmt.Errorf("%s.service.name is required", fieldPath)
		}

		if backend.Service.Port.Number == 0 && backend.Service.Port.Name == "" {
			return fmt.Errorf("%s.service.port: either number or name must be specified", fieldPath)
		}

		if backend.Service.Port.Number != 0 {
			if backend.Service.Port.Number < MinPort || backend.Service.Port.Number > MaxPort {
				return fmt.Errorf(
					"%s.service.port.number must be between %d and %d",
					fieldPath, MinPort, MaxPort,
				)
			}
		}
	}

	return nil
}

// validateTLS validates Ingress TLS configuration.
func (v *IngressValidator) validateTLS(
	tlsConfigs []networkingv1.IngressTLS,
	rules []networkingv1.IngressRule,
) error {
	var errs []string

	// Collect all hosts from rules for cross-reference
	ruleHosts := make(map[string]bool)
	for _, rule := range rules {
		if rule.Host != "" {
			ruleHosts[rule.Host] = true
		}
	}

	for i, tls := range tlsConfigs {
		// Validate secret name
		if tls.SecretName == "" {
			errs = append(errs, fmt.Sprintf("tls[%d].secretName is required", i))
		}

		// Validate that TLS hosts match rule hosts
		for j, host := range tls.Hosts {
			if host == "" {
				errs = append(errs, fmt.Sprintf("tls[%d].hosts[%d] cannot be empty", i, j))
				continue
			}

			if err := validateIngressHost(host); err != nil {
				errs = append(errs, fmt.Sprintf("tls[%d].hosts[%d]: %v", i, j, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	return nil
}

// checkDuplicateHostPaths checks for duplicate host/path combinations within the same Ingress.
func (v *IngressValidator) checkDuplicateHostPaths(rules []networkingv1.IngressRule) error {
	type hostPath struct {
		host     string
		path     string
		pathType string
	}

	seen := make(map[hostPath]bool)

	for _, rule := range rules {
		if rule.HTTP == nil {
			continue
		}

		for _, path := range rule.HTTP.Paths {
			pathType := "Prefix"
			if path.PathType != nil {
				pathType = string(*path.PathType)
			}

			hp := hostPath{
				host:     rule.Host,
				path:     path.Path,
				pathType: pathType,
			}

			if seen[hp] {
				return fmt.Errorf(
					"duplicate host/path combination: host=%q path=%q pathType=%s",
					rule.Host, path.Path, pathType,
				)
			}
			seen[hp] = true
		}
	}

	return nil
}

// checkAPIRouteConflicts checks if the Ingress paths conflict with existing APIRoute CRDs.
// This prevents overlapping path configurations between Ingress and APIRoute resources.
func (v *IngressValidator) checkAPIRouteConflicts(
	ctx context.Context,
	ingress *networkingv1.Ingress,
) error {
	if v.Client == nil {
		return nil
	}

	// List existing APIRoutes in the same namespace
	routes := &avapigwv1alpha1.APIRouteList{}
	if err := v.Client.List(ctx, routes, client.InNamespace(ingress.Namespace)); err != nil {
		return fmt.Errorf("failed to list APIRoutes for conflict check: %w", err)
	}

	existingPaths := buildAPIRoutePaths(routes)
	conflicts := findIngressPathConflicts(ingress.Spec.Rules, existingPaths)

	if len(conflicts) > 0 {
		return fmt.Errorf(
			"ingress %s/%s conflicts with existing APIRoutes: %s",
			ingress.Namespace, ingress.Name, strings.Join(conflicts, "; "),
		)
	}

	return nil
}

// buildAPIRoutePaths extracts all URI paths from APIRoute resources into a map of path to route name.
func buildAPIRoutePaths(routes *avapigwv1alpha1.APIRouteList) map[string]string {
	existingPaths := make(map[string]string)
	for i := range routes.Items {
		route := &routes.Items[i]
		for _, match := range route.Spec.Match {
			if match.URI == nil {
				continue
			}
			if match.URI.Prefix != "" {
				existingPaths[match.URI.Prefix] = route.Name
			}
			if match.URI.Exact != "" {
				existingPaths[match.URI.Exact] = route.Name
			}
		}
	}
	return existingPaths
}

// findIngressPathConflicts checks Ingress rules against existing APIRoute paths
// and returns a list of conflict descriptions.
func findIngressPathConflicts(
	rules []networkingv1.IngressRule,
	existingPaths map[string]string,
) []string {
	var conflicts []string
	for _, rule := range rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			conflicts = appendPathConflicts(conflicts, path.Path, existingPaths)
		}
	}
	return conflicts
}

// appendPathConflicts checks a single Ingress path against existing APIRoute paths
// for exact matches and prefix overlaps, appending any conflicts found.
func appendPathConflicts(
	conflicts []string,
	ingressPath string,
	existingPaths map[string]string,
) []string {
	for existingPath, routeName := range existingPaths {
		if ingressPath == existingPath {
			conflicts = append(conflicts, fmt.Sprintf(
				"path %q conflicts with APIRoute %q",
				ingressPath, routeName,
			))
		} else if pathsOverlap(ingressPath, existingPath) {
			conflicts = append(conflicts, fmt.Sprintf(
				"path %q overlaps with APIRoute %q path %q",
				ingressPath, routeName, existingPath,
			))
		}
	}
	return conflicts
}

// validateIngressHost validates an Ingress hostname.
// Hostnames must be valid DNS names or wildcard DNS names.
func validateIngressHost(host string) error {
	if host == "" {
		return nil
	}

	// Check for wildcard hosts
	if strings.HasPrefix(host, "*.") {
		host = host[2:] // Remove wildcard prefix for validation
		if host == "" {
			return fmt.Errorf("wildcard host must have a domain after '*.'")
		}
	}

	// Basic DNS name validation
	if strings.Contains(host, " ") {
		return fmt.Errorf("host %q contains spaces", host)
	}

	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("host %q must not start or end with a dot", host)
	}

	// Check each label
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("host %q contains empty label", host)
		}
		if len(label) > 63 {
			return fmt.Errorf("host %q label exceeds 63 characters", host)
		}
	}

	return nil
}

// pathsOverlap checks if two paths overlap (one is a prefix of the other).
func pathsOverlap(pathA, pathB string) bool {
	return strings.HasPrefix(pathA, pathB) || strings.HasPrefix(pathB, pathA)
}

// isGRPCIngress checks if the Ingress is configured for gRPC protocol.
func (v *IngressValidator) isGRPCIngress(ingress *networkingv1.Ingress) bool {
	if ingress.Annotations == nil {
		return false
	}
	protocol, ok := ingress.Annotations[annotationProtocol]
	if !ok {
		return false
	}
	return strings.EqualFold(protocol, protocolGRPC)
}

// checkGRPCRouteConflicts checks if the gRPC Ingress conflicts with existing GRPCRoute CRDs.
// This prevents overlapping service/method configurations between Ingress and GRPCRoute resources.
func (v *IngressValidator) checkGRPCRouteConflicts(
	ctx context.Context,
	ingress *networkingv1.Ingress,
) error {
	if v.Client == nil {
		return nil
	}

	// List existing GRPCRoutes in the same namespace
	routes := &avapigwv1alpha1.GRPCRouteList{}
	if err := v.Client.List(ctx, routes, client.InNamespace(ingress.Namespace)); err != nil {
		return fmt.Errorf("failed to list GRPCRoutes for conflict check: %w", err)
	}

	existingServices := buildGRPCRouteServices(routes)
	conflicts := findIngressGRPCConflicts(ingress, existingServices)

	if len(conflicts) > 0 {
		return fmt.Errorf(
			"gRPC ingress %s/%s conflicts with existing GRPCRoutes: %s",
			ingress.Namespace, ingress.Name, strings.Join(conflicts, "; "),
		)
	}

	return nil
}

// grpcRouteService represents a gRPC service/method combination from a GRPCRoute.
type grpcRouteService struct {
	service   string
	method    string
	authority string
	routeName string
}

// extractStringMatchValue extracts the value from a StringMatch, preferring Exact over Prefix.
func extractStringMatchValue(sm *avapigwv1alpha1.StringMatch) string {
	if sm == nil {
		return ""
	}
	if sm.Exact != "" {
		return sm.Exact
	}
	return sm.Prefix
}

// buildGRPCRouteServiceFromMatch creates a grpcRouteService from a GRPCRouteMatch.
func buildGRPCRouteServiceFromMatch(routeName string, match avapigwv1alpha1.GRPCRouteMatch) grpcRouteService {
	return grpcRouteService{
		routeName: routeName,
		service:   extractStringMatchValue(match.Service),
		method:    extractStringMatchValue(match.Method),
		authority: extractStringMatchValue(match.Authority),
	}
}

// buildGRPCRouteServices extracts all service/method combinations from GRPCRoute resources.
func buildGRPCRouteServices(routes *avapigwv1alpha1.GRPCRouteList) []grpcRouteService {
	// Estimate capacity: each route may have multiple matches
	estimatedCap := 0
	for i := range routes.Items {
		estimatedCap += len(routes.Items[i].Spec.Match)
	}
	services := make([]grpcRouteService, 0, estimatedCap)
	for i := range routes.Items {
		route := &routes.Items[i]
		for _, match := range route.Spec.Match {
			services = append(services, buildGRPCRouteServiceFromMatch(route.Name, match))
		}
	}
	return services
}

// stringsOverlap checks if two strings overlap (equal or one is prefix of the other).
func stringsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// checkMethodConflict checks if methods conflict (empty matches all).
func checkMethodConflict(ingressMethod, existingMethod string) bool {
	if ingressMethod == "" || existingMethod == "" {
		return true
	}
	return stringsOverlap(ingressMethod, existingMethod)
}

// checkServiceConflict checks if services conflict and returns a conflict message if so.
func checkServiceConflict(host, ingressService, ingressMethod string, existing grpcRouteService) string {
	// Both have services - check for overlap
	if ingressService != "" && existing.service != "" {
		if stringsOverlap(ingressService, existing.service) && checkMethodConflict(ingressMethod, existing.method) {
			return fmt.Sprintf("host %q with service %q conflicts with GRPCRoute %q",
				host, ingressService, existing.routeName)
		}
		return ""
	}
	// Both match all services
	if ingressService == "" && existing.service == "" {
		return fmt.Sprintf("host %q conflicts with GRPCRoute %q (both match all services)",
			host, existing.routeName)
	}
	return ""
}

// findIngressGRPCConflicts checks Ingress gRPC configuration against existing GRPCRoute services
// and returns a list of conflict descriptions.
func findIngressGRPCConflicts(
	ingress *networkingv1.Ingress,
	existingServices []grpcRouteService,
) []string {
	var conflicts []string

	annotations := ingress.Annotations
	if annotations == nil {
		return conflicts
	}

	ingressService := annotations["avapigw.io/grpc-service"]
	ingressMethod := annotations["avapigw.io/grpc-method"]

	for _, rule := range ingress.Spec.Rules {
		if rule.Host == "" {
			continue
		}
		for _, existing := range existingServices {
			if existing.authority == "" || !stringsOverlap(rule.Host, existing.authority) {
				continue
			}
			if conflict := checkServiceConflict(rule.Host, ingressService, ingressMethod, existing); conflict != "" {
				conflicts = append(conflicts, conflict)
			}
		}
	}

	return conflicts
}
