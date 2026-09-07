// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MCPBackendSpec defines the desired state of MCPBackend. It mirrors the
// gateway config.MCPBackend (MCPUpstream) type (HUB-503) and reuses the shared
// backend infrastructure via MCPBackendToBackend in the gateway.
type MCPBackendSpec struct {
	// Hosts contains the upstream host configurations.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Hosts []BackendHost `json:"hosts"`

	// Transport selects the upstream transport. Only "streamable-http" is
	// supported in this iteration.
	// +optional
	Transport string `json:"transport,omitempty"`

	// Era pins the protocol era: "modern", "legacy" or "" (auto-detect).
	// +kubebuilder:validation:Enum=modern;legacy
	// +optional
	Era string `json:"era,omitempty"`

	// PinnedVersion pins a specific protocol version, bypassing probing (HUB-724).
	// +optional
	PinnedVersion string `json:"pinnedVersion,omitempty"`

	// NamespacePrefix is the prefix applied when namespacing this upstream's
	// primitives (HUB-162). Defaults to the resource name when unset.
	// +optional
	NamespacePrefix string `json:"namespacePrefix,omitempty"`

	// Separator overrides the global namespacing separator for this upstream
	// (HUB-162). Must be a subset of A-Za-z0-9_.-.
	// +optional
	Separator string `json:"separator,omitempty"`

	// Allow restricts which primitives are exposed from this upstream
	// (HUB-503 allow list). Empty means allow all (subject to Deny).
	// +optional
	Allow []string `json:"allow,omitempty"`

	// Deny excludes primitives from this upstream (HUB-503 deny list).
	// +optional
	Deny []string `json:"deny,omitempty"`

	// TrustLevel marks the upstream as "trusted" or "untrusted" (HUB-401).
	// +kubebuilder:validation:Enum=trusted;untrusted
	// +optional
	TrustLevel string `json:"trustLevel,omitempty"`

	// HealthCheck contains health check configuration.
	// +optional
	HealthCheck *HealthCheckConfig `json:"healthCheck,omitempty"`

	// LoadBalancer contains load balancer configuration.
	// +optional
	LoadBalancer *LoadBalancerConfig `json:"loadBalancer,omitempty"`

	// TLS contains TLS configuration for connecting to the upstream
	// (including Vault PKI mTLS, HUB-309).
	// +optional
	TLS *BackendTLSConfig `json:"tls,omitempty"`

	// CircuitBreaker configures circuit breaking for this upstream (HUB-504).
	// +optional
	CircuitBreaker *CircuitBreakerConfig `json:"circuitBreaker,omitempty"`

	// Credential configures the independent upstream credential source; the
	// downstream client token is never forwarded (HUB-303/304).
	// +optional
	Credential *BackendAuthConfig `json:"credential,omitempty"`

	// Timeouts configures per-method/per-tool timeouts (HUB-243).
	// +optional
	Timeouts *MCPTimeouts `json:"timeouts,omitempty"`

	// CacheTTLClamp clamps aggregated cache TTLs for this upstream (HUB-182).
	// +optional
	CacheTTLClamp *MCPTTLClamp `json:"cacheTTLClamp,omitempty"`

	// RateLimit configures rate limiting for this upstream.
	// +optional
	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`

	// Path is the upstream MCP endpoint path. Default: /mcp.
	// +optional
	Path string `json:"path,omitempty"`
}

// MCPTimeouts configures per-method and per-tool timeouts for an upstream
// (HUB-243). It mirrors the gateway config.MCPTimeouts type.
type MCPTimeouts struct {
	// PerMethod maps an MCP method name to its timeout.
	// +optional
	PerMethod map[string]Duration `json:"perMethod,omitempty"`

	// PerTool maps a de-namespaced tool name to its timeout.
	// +optional
	PerTool map[string]Duration `json:"perTool,omitempty"`

	// Default is the fallback timeout when no per-method/per-tool override applies.
	// +optional
	Default Duration `json:"default,omitempty"`
}

// MCPTTLClamp clamps aggregated cache TTLs to a configured range (HUB-182).
// It mirrors the gateway config.MCPTTLClamp type.
type MCPTTLClamp struct {
	// Min is the lower clamp for cache TTLs.
	// +optional
	Min Duration `json:"min,omitempty"`

	// Max is the upper clamp for cache TTLs.
	// +optional
	Max Duration `json:"max,omitempty"`
}

// MCPBackendStatus defines the observed state of MCPBackend.
type MCPBackendStatus struct {
	// Conditions represent the latest available observations of the MCPBackend's state.
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// HealthyHosts is the number of healthy hosts.
	// +optional
	HealthyHosts int `json:"healthyHosts,omitempty"`

	// TotalHosts is the total number of hosts.
	// +optional
	TotalHosts int `json:"totalHosts,omitempty"`

	// LastHealthCheck is the timestamp of the last health check.
	// +optional
	LastHealthCheck *metav1.Time `json:"lastHealthCheck,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mcpbe
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Healthy",type="string",JSONPath=".status.conditions[?(@.type=='Healthy')].status"
// +kubebuilder:printcolumn:name="Hosts",type="string",JSONPath=".status.healthyHosts"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// MCPBackend is the Schema for the mcpbackends API.
type MCPBackend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MCPBackendSpec   `json:"spec,omitempty"`
	Status MCPBackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MCPBackendList contains a list of MCPBackend.
type MCPBackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPBackend `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MCPBackend{}, &MCPBackendList{})
}
