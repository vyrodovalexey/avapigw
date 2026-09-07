// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MCPRouteSpec defines the desired state of MCPRoute. It mirrors the gateway
// config.MCPRoute type (HUB-503): routing-specific fields plus the shared
// cross-cutting middleware configuration reused across route kinds.
type MCPRouteSpec struct {
	// Match contains the matching conditions for this route.
	// +optional
	Match []MCPRouteMatch `json:"match,omitempty"`

	// Upstreams lists the MCPBackend names this route fans out to (legacy,
	// equal weight). Mutually exclusive with WeightedUpstreams.
	// +optional
	Upstreams []string `json:"upstreams,omitempty"`

	// WeightedUpstreams lists MCPBackend references with traffic weights for
	// single-upstream selection (canary / A-B). Mutually exclusive with
	// Upstreams. Aggregation and subscription fan-out still cover ALL
	// referenced upstreams regardless of weight.
	// +optional
	WeightedUpstreams []MCPUpstreamRef `json:"weightedUpstreams,omitempty"`

	// Timeout is the request timeout for this route.
	// +optional
	Timeout Duration `json:"timeout,omitempty"`

	// Retries contains retry policy configuration.
	// +optional
	Retries *RetryPolicy `json:"retries,omitempty"`

	// Headers contains header manipulation configuration.
	// +optional
	Headers *HeaderManipulation `json:"headers,omitempty"`

	// RateLimit contains route-level rate limiting configuration.
	// +optional
	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`

	// Cache contains caching configuration.
	// +optional
	Cache *CacheConfig `json:"cache,omitempty"`

	// CORS configures CORS for this MCP route (overrides global).
	// +optional
	CORS *CORSConfig `json:"cors,omitempty"`

	// Security configures security headers for this MCP route (overrides global).
	// +optional
	Security *SecurityConfig `json:"security,omitempty"`

	// TLS configures route-level TLS certificate override for this MCP route.
	// +optional
	TLS *RouteTLSConfig `json:"tls,omitempty"`

	// Authentication configures route-level authentication.
	// +optional
	Authentication *AuthenticationConfig `json:"authentication,omitempty"`

	// Authorization configures route-level authorization.
	// +optional
	Authorization *AuthorizationConfig `json:"authorization,omitempty"`

	// ScopeMap maps a primitive or method to the OAuth scopes required to
	// invoke it (HUB-305/306).
	// +optional
	ScopeMap map[string][]string `json:"scopeMap,omitempty"`
}

// MCPUpstreamRef references an MCPBackend with an optional traffic weight.
// It mirrors config.MCPUpstreamRef so weighted MCP routing follows the same
// 0-100 / sum-to-100 semantics as APIRoute destinations.
type MCPUpstreamRef struct {
	// Name is the referenced MCPBackend name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Weight is the relative traffic weight (0-100). Zero-weight refs receive
	// no traffic when any sibling has a positive weight; when all weights are
	// zero, selection is uniform.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	Weight int `json:"weight,omitempty"`
}

// MCPRouteMatch represents matching conditions for an MCP route. Matches are
// derivable from mirrored headers alone (HUB-148): Method mirrors Mcp-Method
// and Name mirrors Mcp-Name.
type MCPRouteMatch struct {
	// Path matches the HTTP path for the MCP endpoint.
	// +optional
	Path *StringMatch `json:"path,omitempty"`

	// Method matches the MCP method (mirrored into the Mcp-Method header).
	// +optional
	Method string `json:"method,omitempty"`

	// Name matches the MCP primitive name (mirrored into the Mcp-Name
	// header) for tools/call, resources/read and prompts/get.
	// +optional
	Name *StringMatch `json:"name,omitempty"`

	// Headers matches HTTP headers.
	// +optional
	Headers []HeaderMatch `json:"headers,omitempty"`
}

// MCPRouteStatus defines the observed state of MCPRoute.
type MCPRouteStatus struct {
	// Conditions represent the latest available observations of the MCPRoute's state.
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// AppliedGateways is the list of gateways where this route has been applied.
	// +optional
	AppliedGateways []AppliedGateway `json:"appliedGateways,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mcpr
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// MCPRoute is the Schema for the mcproutes API.
type MCPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MCPRouteSpec   `json:"spec,omitempty"`
	Status MCPRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MCPRouteList contains a list of MCPRoute.
type MCPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPRoute `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MCPRoute{}, &MCPRouteList{})
}
