// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import "time"

// ============================================================================
// Controller Names
// ============================================================================

// Controller names used in RouteParentStatus to identify which controller
// accepted the route. These follow the format: <domain>/<controller-type>.
const (
	// GatewayControllerName is the controller name for Gateway-related operations.
	// Used in RouteParentStatus.ControllerName to identify the gateway controller.
	GatewayControllerName = "avapigw.vyrodovalexey.github.com/gateway-controller"
)

// ============================================================================
// Finalizer Names
// ============================================================================

// Finalizer names follow the pattern: <domain>/<resource-type>-finalizer.
// These are used to ensure cleanup operations complete before resource deletion.
const (
	// GatewayFinalizerName is the finalizer for Gateway resources.
	GatewayFinalizerName = "avapigw.vyrodovalexey.github.com/gateway-finalizer"

	// HTTPRouteFinalizerName is the finalizer for HTTPRoute resources.
	HTTPRouteFinalizerName = "avapigw.vyrodovalexey.github.com/httproute-finalizer"

	// GRPCRouteFinalizerName is the finalizer for GRPCRoute resources.
	GRPCRouteFinalizerName = "avapigw.vyrodovalexey.github.com/grpcroute-finalizer"

	// TCPRouteFinalizerName is the finalizer for TCPRoute resources.
	TCPRouteFinalizerName = "avapigw.vyrodovalexey.github.com/tcproute-finalizer"

	// TLSRouteFinalizerName is the finalizer for TLSRoute resources.
	TLSRouteFinalizerName = "avapigw.vyrodovalexey.github.com/tlsroute-finalizer"

	// AuthPolicyFinalizerName is the finalizer for AuthPolicy resources.
	AuthPolicyFinalizerName = "avapigw.vyrodovalexey.github.com/authpolicy-finalizer"

	// RateLimitPolicyFinalizerName is the finalizer for RateLimitPolicy resources.
	RateLimitPolicyFinalizerName = "avapigw.vyrodovalexey.github.com/ratelimitpolicy-finalizer"

	// BackendFinalizerName is the finalizer for Backend resources.
	BackendFinalizerName = "avapigw.vyrodovalexey.github.com/backend-finalizer"

	// TLSConfigFinalizerName is the finalizer for TLSConfig resources.
	TLSConfigFinalizerName = "avapigw.vyrodovalexey.github.com/tlsconfig-finalizer"

	// VaultSecretFinalizerName is the finalizer for VaultSecret resources.
	//nolint:gosec // G101: This is a Kubernetes finalizer name, not credentials
	VaultSecretFinalizerName = "avapigw.vyrodovalexey.github.com/vaultsecret-finalizer"
)

// ============================================================================
// Reconcile Timeouts
// ============================================================================

// Reconcile timeout values define the maximum duration for a single reconciliation.
// These prevent hanging reconciliations and ensure timely error handling.
const (
	// DefaultReconcileTimeout is the default timeout for reconciliation operations.
	DefaultReconcileTimeout = 30 * time.Second

	// GatewayReconcileTimeout is the timeout for Gateway reconciliation.
	GatewayReconcileTimeout = 30 * time.Second

	// HTTPRouteReconcileTimeout is the timeout for HTTPRoute reconciliation.
	HTTPRouteReconcileTimeout = 30 * time.Second

	// GRPCRouteReconcileTimeout is the timeout for GRPCRoute reconciliation.
	GRPCRouteReconcileTimeout = 30 * time.Second

	// TCPRouteReconcileTimeout is the timeout for TCPRoute reconciliation.
	TCPRouteReconcileTimeout = 30 * time.Second

	// TLSRouteReconcileTimeout is the timeout for TLSRoute reconciliation.
	TLSRouteReconcileTimeout = 30 * time.Second

	// AuthPolicyReconcileTimeout is the timeout for AuthPolicy reconciliation.
	AuthPolicyReconcileTimeout = 30 * time.Second

	// RateLimitPolicyReconcileTimeout is the timeout for RateLimitPolicy reconciliation.
	RateLimitPolicyReconcileTimeout = 30 * time.Second

	// BackendReconcileTimeout is the timeout for Backend reconciliation.
	BackendReconcileTimeout = 30 * time.Second

	// TLSConfigReconcileTimeout is the timeout for TLSConfig reconciliation.
	TLSConfigReconcileTimeout = 30 * time.Second

	// VaultSecretReconcileTimeout is the timeout for VaultSecret reconciliation.
	VaultSecretReconcileTimeout = 60 * time.Second
)

// ============================================================================
// Metrics Configuration
// ============================================================================

// Metrics namespace and subsystem for Prometheus metrics.
const (
	// MetricsNamespace is the Prometheus metrics namespace for all avapigw metrics.
	MetricsNamespace = "avapigw"

	// MetricsSubsystemController is the Prometheus metrics subsystem for controller metrics.
	MetricsSubsystemController = "controller"

	// MetricsSubsystemGateway is the Prometheus metrics subsystem for gateway metrics.
	MetricsSubsystemGateway = "gateway"
)

// ============================================================================
// Common Label Keys
// ============================================================================

// Label keys used for Kubernetes resource labels and annotations.
const (
	// LabelKeyManagedBy is the label key indicating which controller manages a resource.
	LabelKeyManagedBy = "app.kubernetes.io/managed-by"

	// LabelKeyComponent is the label key indicating the component type.
	LabelKeyComponent = "app.kubernetes.io/component"

	// LabelKeyPartOf is the label key indicating which application the resource is part of.
	LabelKeyPartOf = "app.kubernetes.io/part-of"

	// LabelKeyInstance is the label key for the instance name.
	LabelKeyInstance = "app.kubernetes.io/instance"

	// LabelKeyVersion is the label key for the version.
	LabelKeyVersion = "app.kubernetes.io/version"

	// LabelValueManagedBy is the default value for the managed-by label.
	LabelValueManagedBy = "avapigw"
)

// ============================================================================
// Annotation Keys
// ============================================================================

// Annotation keys used for Kubernetes resource annotations.
const (
	// AnnotationKeyLastReconciled is the annotation key for the last reconciliation timestamp.
	AnnotationKeyLastReconciled = "avapigw.vyrodovalexey.github.com/last-reconciled"

	// AnnotationKeyReconcileGeneration is the annotation key for the reconciled generation.
	AnnotationKeyReconcileGeneration = "avapigw.vyrodovalexey.github.com/reconcile-generation"
)

// ============================================================================
// Pagination Configuration
// ============================================================================

// Pagination configuration for list operations.
const (
	// DefaultListPageSize is the default page size for paginated list operations.
	DefaultListPageSize = 100
)

// ============================================================================
// Event Reasons
// ============================================================================

// Event reasons for Kubernetes events.
const (
	// EventReasonReconciled indicates successful reconciliation.
	EventReasonReconciled = "Reconciled"

	// EventReasonReconcileError indicates a reconciliation error.
	EventReasonReconcileError = "ReconcileError"

	// EventReasonDeleting indicates the resource is being deleted.
	EventReasonDeleting = "Deleting"

	// EventReasonFinalizerError indicates a finalizer operation error.
	EventReasonFinalizerError = "FinalizerError"

	// EventReasonBackendNotFound indicates a backend reference was not found.
	EventReasonBackendNotFound = "BackendNotFound"

	// EventReasonValidationError indicates a validation error.
	EventReasonValidationError = "ValidationError"

	// EventReasonDependencyError indicates a dependency error.
	EventReasonDependencyError = "DependencyError"
)
