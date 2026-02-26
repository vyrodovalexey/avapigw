// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GRPCBackendSpec defines the desired state of GRPCBackend.
type GRPCBackendSpec struct {
	// Hosts contains the backend host configurations.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Hosts []BackendHost `json:"hosts"`

	// HealthCheck contains gRPC health check configuration.
	// +optional
	HealthCheck *GRPCHealthCheckConfig `json:"healthCheck,omitempty"`

	// LoadBalancer contains load balancer configuration.
	// +optional
	LoadBalancer *LoadBalancerConfig `json:"loadBalancer,omitempty"`

	// TLS contains TLS configuration for backend connections.
	// +optional
	TLS *BackendTLSConfig `json:"tls,omitempty"`

	// ConnectionPool contains connection pool configuration.
	// +optional
	ConnectionPool *GRPCConnectionPoolConfig `json:"connectionPool,omitempty"`

	// CircuitBreaker configures circuit breaker for this gRPC backend.
	// +optional
	CircuitBreaker *CircuitBreakerConfig `json:"circuitBreaker,omitempty"`

	// Authentication configures authentication for gRPC backend connections.
	// +optional
	Authentication *BackendAuthConfig `json:"authentication,omitempty"`

	// MaxSessions configures maximum concurrent sessions for this backend.
	// +optional
	MaxSessions *MaxSessionsConfig `json:"maxSessions,omitempty"`

	// RateLimit configures rate limiting for this backend.
	// +optional
	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`

	// Transform contains gRPC transformation configuration for this backend.
	// +optional
	Transform *GRPCBackendTransformConfig `json:"transform,omitempty"`

	// Cache contains caching configuration for this backend.
	// +optional
	Cache *BackendCacheConfig `json:"cache,omitempty"`

	// Encoding contains encoding configuration for this backend.
	// +optional
	Encoding *BackendEncodingConfig `json:"encoding,omitempty"`
}

// GRPCHealthCheckConfig contains gRPC health check configuration.
type GRPCHealthCheckConfig struct {
	// Enabled indicates whether health checking is enabled.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// Service is the service name to check. Empty string checks overall health.
	// Used only when useHTTP is false (default gRPC health check mode).
	// +optional
	Service string `json:"service,omitempty"`

	// UseHTTP switches health checking from gRPC protocol to HTTP GET.
	// When true, the health checker sends HTTP GET requests to httpPath
	// on httpPort instead of using grpc.health.v1.Health/Check.
	// This is useful for backends that require authentication on gRPC
	// but expose an unauthenticated HTTP health/monitoring endpoint.
	// +optional
	UseHTTP bool `json:"useHTTP,omitempty"`

	// HTTPPath is the HTTP path for health checks when useHTTP is true.
	// +kubebuilder:default="/healthz"
	// +optional
	HTTPPath string `json:"httpPath,omitempty"`

	// HTTPPort is the port for HTTP health checks when useHTTP is true.
	// If not set, the backend's main port is used.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	HTTPPort int `json:"httpPort,omitempty"`

	// Interval is the health check interval.
	// +optional
	Interval Duration `json:"interval,omitempty"`

	// Timeout is the health check timeout.
	// +optional
	Timeout Duration `json:"timeout,omitempty"`

	// HealthyThreshold is the number of consecutive successes to mark healthy.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=2
	// +optional
	HealthyThreshold int `json:"healthyThreshold,omitempty"`

	// UnhealthyThreshold is the number of consecutive failures to mark unhealthy.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	// +optional
	UnhealthyThreshold int `json:"unhealthyThreshold,omitempty"`
}

// GRPCConnectionPoolConfig contains gRPC connection pool configuration.
type GRPCConnectionPoolConfig struct {
	// MaxIdleConns is the maximum number of idle connections per host.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=10
	// +optional
	MaxIdleConns int `json:"maxIdleConns,omitempty"`

	// MaxConnsPerHost is the maximum number of connections per host.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=100
	// +optional
	MaxConnsPerHost int `json:"maxConnsPerHost,omitempty"`

	// IdleConnTimeout is the maximum time a connection can be idle.
	// +optional
	IdleConnTimeout Duration `json:"idleConnTimeout,omitempty"`
}

// GRPCBackendStatus defines the observed state of GRPCBackend.
type GRPCBackendStatus struct {
	// Conditions represent the latest available observations of the GRPCBackend's state.
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
// +kubebuilder:resource:shortName=gbe
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Healthy",type="string",JSONPath=".status.conditions[?(@.type=='Healthy')].status"
// +kubebuilder:printcolumn:name="Hosts",type="string",JSONPath=".status.healthyHosts"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GRPCBackend is the Schema for the grpcbackends API.
type GRPCBackend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GRPCBackendSpec   `json:"spec,omitempty"`
	Status GRPCBackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GRPCBackendList contains a list of GRPCBackend.
type GRPCBackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GRPCBackend `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GRPCBackend{}, &GRPCBackendList{})
}
