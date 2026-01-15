package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// Backend CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=be
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Healthy",type="integer",JSONPath=".status.healthyEndpoints"
// +kubebuilder:printcolumn:name="Total",type="integer",JSONPath=".status.totalEndpoints"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Backend is the Schema for the backends API.
// Backend defines a backend service with load balancing, health checking,
// and connection pooling configuration.
type Backend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackendSpec   `json:"spec,omitempty"`
	Status BackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BackendList contains a list of Backend
type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Backend `json:"items"`
}

// BackendSpec defines the desired state of Backend
type BackendSpec struct {
	// Service references a Kubernetes Service as the backend.
	// Either Service or Endpoints must be specified, but not both.
	// +optional
	Service *ServiceRef `json:"service,omitempty"`

	// Endpoints defines direct endpoints for the backend.
	// Either Service or Endpoints must be specified, but not both.
	// +kubebuilder:validation:MaxItems=100
	// +optional
	Endpoints []EndpointConfig `json:"endpoints,omitempty"`

	// LoadBalancing defines the load balancing configuration.
	// +optional
	LoadBalancing *LoadBalancingConfig `json:"loadBalancing,omitempty"`

	// HealthCheck defines the health check configuration.
	// +optional
	HealthCheck *HealthCheckConfig `json:"healthCheck,omitempty"`

	// ConnectionPool defines the connection pool configuration.
	// +optional
	ConnectionPool *ConnectionPoolConfig `json:"connectionPool,omitempty"`

	// CircuitBreaker defines the circuit breaker configuration.
	// +optional
	CircuitBreaker *CircuitBreakerConfig `json:"circuitBreaker,omitempty"`

	// OutlierDetection defines the outlier detection configuration.
	// +optional
	OutlierDetection *OutlierDetectionConfig `json:"outlierDetection,omitempty"`

	// TLS defines the TLS configuration for backend connections.
	// +optional
	TLS *BackendTLSConfig `json:"tls,omitempty"`
}

// ServiceRef references a Kubernetes Service
type ServiceRef struct {
	// Name is the name of the Service.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the namespace of the Service.
	// If not specified, the namespace of the Backend is used.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// Port is the port of the Service.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// EndpointConfig defines a direct endpoint
type EndpointConfig struct {
	// Address is the IP address or hostname of the endpoint.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Address string `json:"address"`

	// Port is the port of the endpoint.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Weight specifies the proportion of traffic to forward to this endpoint.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000000
	// +kubebuilder:default=1
	// +optional
	Weight *int32 `json:"weight,omitempty"`
}

// ============================================================================
// Load Balancing Configuration
// ============================================================================

// LoadBalancingConfig defines load balancing configuration
type LoadBalancingConfig struct {
	// Algorithm is the load balancing algorithm.
	// +kubebuilder:validation:Enum=RoundRobin;LeastConnections;Random;ConsistentHash
	// +kubebuilder:default=RoundRobin
	// +optional
	Algorithm *LoadBalancingAlgorithm `json:"algorithm,omitempty"`

	// ConsistentHash defines consistent hash configuration.
	// Required when Algorithm is ConsistentHash.
	// +optional
	ConsistentHash *ConsistentHashConfig `json:"consistentHash,omitempty"`
}

// LoadBalancingAlgorithm defines the load balancing algorithm
// +kubebuilder:validation:Enum=RoundRobin;LeastConnections;Random;ConsistentHash
type LoadBalancingAlgorithm string

const (
	// LoadBalancingRoundRobin distributes requests in round-robin fashion
	LoadBalancingRoundRobin LoadBalancingAlgorithm = "RoundRobin"
	// LoadBalancingLeastConnections sends requests to the endpoint with least connections
	LoadBalancingLeastConnections LoadBalancingAlgorithm = "LeastConnections"
	// LoadBalancingRandom distributes requests randomly
	LoadBalancingRandom LoadBalancingAlgorithm = "Random"
	// LoadBalancingConsistentHash uses consistent hashing
	LoadBalancingConsistentHash LoadBalancingAlgorithm = "ConsistentHash"
)

// ConsistentHashConfig defines consistent hash configuration
type ConsistentHashConfig struct {
	// Type defines the type of consistent hash.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Header;Cookie;SourceIP
	Type ConsistentHashType `json:"type"`

	// Header is the name of the header to use for consistent hashing.
	// Required when Type is Header.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Header *string `json:"header,omitempty"`

	// Cookie is the name of the cookie to use for consistent hashing.
	// Required when Type is Cookie.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +optional
	Cookie *string `json:"cookie,omitempty"`

	// MinimumRingSize is the minimum size of the hash ring.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=8388608
	// +kubebuilder:default=1024
	// +optional
	MinimumRingSize *int32 `json:"minimumRingSize,omitempty"`
}

// ConsistentHashType defines the type of consistent hash
// +kubebuilder:validation:Enum=Header;Cookie;SourceIP
type ConsistentHashType string

const (
	// ConsistentHashHeader uses a header value for hashing
	ConsistentHashHeader ConsistentHashType = "Header"
	// ConsistentHashCookie uses a cookie value for hashing
	ConsistentHashCookie ConsistentHashType = "Cookie"
	// ConsistentHashSourceIP uses the source IP for hashing
	ConsistentHashSourceIP ConsistentHashType = "SourceIP"
)

// ============================================================================
// Health Check Configuration
// ============================================================================

// HealthCheckConfig defines health check configuration
type HealthCheckConfig struct {
	// Enabled indicates whether health checking is enabled.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Interval is the interval between health checks.
	// +kubebuilder:default="10s"
	// +optional
	Interval *Duration `json:"interval,omitempty"`

	// Timeout is the timeout for a health check.
	// +kubebuilder:default="5s"
	// +optional
	Timeout *Duration `json:"timeout,omitempty"`

	// HealthyThreshold is the number of consecutive successful health checks
	// required before considering an endpoint healthy.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	// +kubebuilder:default=2
	// +optional
	HealthyThreshold *int32 `json:"healthyThreshold,omitempty"`

	// UnhealthyThreshold is the number of consecutive failed health checks
	// required before considering an endpoint unhealthy.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	// +kubebuilder:default=3
	// +optional
	UnhealthyThreshold *int32 `json:"unhealthyThreshold,omitempty"`

	// HTTP defines HTTP health check configuration.
	// +optional
	HTTP *HTTPHealthCheckConfig `json:"http,omitempty"`

	// TCP defines TCP health check configuration.
	// +optional
	TCP *TCPHealthCheckConfig `json:"tcp,omitempty"`

	// GRPC defines gRPC health check configuration.
	// +optional
	GRPC *GRPCHealthCheckConfig `json:"grpc,omitempty"`
}

// HTTPHealthCheckConfig defines HTTP health check configuration
type HTTPHealthCheckConfig struct {
	// Path is the HTTP path to use for health checks.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Path string `json:"path"`

	// Host is the value of the Host header in the HTTP health check request.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Host *string `json:"host,omitempty"`

	// Method is the HTTP method to use for health checks.
	// +kubebuilder:validation:Enum=GET;HEAD
	// +kubebuilder:default=GET
	// +optional
	Method *string `json:"method,omitempty"`

	// ExpectedStatuses is the list of HTTP status codes that indicate a healthy endpoint.
	// +kubebuilder:validation:MaxItems=10
	// +optional
	ExpectedStatuses []int32 `json:"expectedStatuses,omitempty"`
}

// TCPHealthCheckConfig defines TCP health check configuration
type TCPHealthCheckConfig struct {
	// Send is the data to send for the health check.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Send *string `json:"send,omitempty"`

	// Receive is the expected response data.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Receive *string `json:"receive,omitempty"`
}

// GRPCHealthCheckConfig defines gRPC health check configuration
type GRPCHealthCheckConfig struct {
	// Service is the gRPC service name to use for health checks.
	// If not specified, the standard gRPC health checking protocol is used.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Service *string `json:"service,omitempty"`
}

// ============================================================================
// Connection Pool Configuration
// ============================================================================

// ConnectionPoolConfig defines connection pool configuration
type ConnectionPoolConfig struct {
	// HTTP defines HTTP connection pool settings.
	// +optional
	HTTP *HTTPConnectionPoolConfig `json:"http,omitempty"`

	// TCP defines TCP connection pool settings.
	// +optional
	TCP *TCPConnectionPoolConfig `json:"tcp,omitempty"`
}

// HTTPConnectionPoolConfig defines HTTP connection pool configuration
type HTTPConnectionPoolConfig struct {
	// MaxConnections is the maximum number of connections to the backend.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000000
	// +kubebuilder:default=100
	// +optional
	MaxConnections *int32 `json:"maxConnections,omitempty"`

	// MaxPendingRequests is the maximum number of pending requests.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000000
	// +kubebuilder:default=100
	// +optional
	MaxPendingRequests *int32 `json:"maxPendingRequests,omitempty"`

	// MaxRequestsPerConnection is the maximum number of requests per connection.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000000
	// +kubebuilder:default=0
	// +optional
	MaxRequestsPerConnection *int32 `json:"maxRequestsPerConnection,omitempty"`

	// IdleTimeout is the idle timeout for connections.
	// +kubebuilder:default="60s"
	// +optional
	IdleTimeout *Duration `json:"idleTimeout,omitempty"`

	// H2UpgradePolicy specifies the HTTP/2 upgrade policy.
	// +kubebuilder:validation:Enum=DO_NOT_UPGRADE;UPGRADE
	// +kubebuilder:default=DO_NOT_UPGRADE
	// +optional
	H2UpgradePolicy *H2UpgradePolicy `json:"h2UpgradePolicy,omitempty"`

	// UseClientProtocol indicates whether to use the client's protocol.
	// +kubebuilder:default=false
	// +optional
	UseClientProtocol *bool `json:"useClientProtocol,omitempty"`
}

// H2UpgradePolicy defines HTTP/2 upgrade policy
// +kubebuilder:validation:Enum=DO_NOT_UPGRADE;UPGRADE
type H2UpgradePolicy string

const (
	// H2UpgradePolicyDoNotUpgrade does not upgrade to HTTP/2
	H2UpgradePolicyDoNotUpgrade H2UpgradePolicy = "DO_NOT_UPGRADE"
	// H2UpgradePolicyUpgrade upgrades to HTTP/2
	H2UpgradePolicyUpgrade H2UpgradePolicy = "UPGRADE"
)

// TCPConnectionPoolConfig defines TCP connection pool configuration
type TCPConnectionPoolConfig struct {
	// MaxConnections is the maximum number of connections to the backend.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000000
	// +kubebuilder:default=100
	// +optional
	MaxConnections *int32 `json:"maxConnections,omitempty"`

	// ConnectTimeout is the timeout for establishing a connection.
	// +kubebuilder:default="10s"
	// +optional
	ConnectTimeout *Duration `json:"connectTimeout,omitempty"`

	// TCPKeepalive defines TCP keepalive settings.
	// +optional
	TCPKeepalive *TCPKeepaliveConfig `json:"tcpKeepalive,omitempty"`
}

// TCPKeepaliveConfig defines TCP keepalive configuration
type TCPKeepaliveConfig struct {
	// Probes is the number of keepalive probes to send.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	// +optional
	Probes *int32 `json:"probes,omitempty"`

	// Time is the time before sending keepalive probes.
	// +optional
	Time *Duration `json:"time,omitempty"`

	// Interval is the interval between keepalive probes.
	// +optional
	Interval *Duration `json:"interval,omitempty"`
}

// ============================================================================
// Circuit Breaker Configuration
// ============================================================================

// CircuitBreakerConfig defines circuit breaker configuration
type CircuitBreakerConfig struct {
	// Enabled indicates whether circuit breaking is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// ConsecutiveErrors is the number of consecutive errors before opening the circuit.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=5
	// +optional
	ConsecutiveErrors *int32 `json:"consecutiveErrors,omitempty"`

	// Interval is the time interval for counting errors.
	// +kubebuilder:default="30s"
	// +optional
	Interval *Duration `json:"interval,omitempty"`

	// BaseEjectionTime is the base time an endpoint is ejected.
	// +kubebuilder:default="30s"
	// +optional
	BaseEjectionTime *Duration `json:"baseEjectionTime,omitempty"`

	// MaxEjectionPercent is the maximum percentage of endpoints that can be ejected.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=50
	// +optional
	MaxEjectionPercent *int32 `json:"maxEjectionPercent,omitempty"`
}

// ============================================================================
// Outlier Detection Configuration
// ============================================================================

// OutlierDetectionConfig defines outlier detection configuration
type OutlierDetectionConfig struct {
	// Enabled indicates whether outlier detection is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Consecutive5xxErrors is the number of consecutive 5xx errors before ejection.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=5
	// +optional
	Consecutive5xxErrors *int32 `json:"consecutive5xxErrors,omitempty"`

	// ConsecutiveGatewayErrors is the number of consecutive gateway errors before ejection.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=5
	// +optional
	ConsecutiveGatewayErrors *int32 `json:"consecutiveGatewayErrors,omitempty"`

	// Interval is the time interval for outlier detection analysis.
	// +kubebuilder:default="10s"
	// +optional
	Interval *Duration `json:"interval,omitempty"`

	// BaseEjectionTime is the base time an endpoint is ejected.
	// +kubebuilder:default="30s"
	// +optional
	BaseEjectionTime *Duration `json:"baseEjectionTime,omitempty"`

	// MaxEjectionPercent is the maximum percentage of endpoints that can be ejected.
	// +kubebuilder:default=10
	// +optional
	MaxEjectionPercent *int32 `json:"maxEjectionPercent,omitempty"`

	// SplitExternalLocalOriginErrors enables splitting of local origin errors.
	// +kubebuilder:default=false
	// +optional
	SplitExternalLocalOriginErrors *bool `json:"splitExternalLocalOriginErrors,omitempty"`
}

// ============================================================================
// Backend TLS Configuration
// ============================================================================

// BackendTLSConfig defines TLS configuration for backend connections
type BackendTLSConfig struct {
	// Mode defines the TLS mode for backend connections.
	// +kubebuilder:validation:Enum=Simple;Mutual;Insecure
	// +kubebuilder:default=Simple
	// +optional
	Mode *BackendTLSMode `json:"mode,omitempty"`

	// CertificateRef references a Secret containing the client certificate.
	// Required when Mode is Mutual.
	// +optional
	CertificateRef *SecretObjectReference `json:"certificateRef,omitempty"`

	// CACertificateRef references a Secret containing the CA certificate.
	// +optional
	CACertificateRef *SecretObjectReference `json:"caCertificateRef,omitempty"`

	// SNI is the Server Name Indication to use for TLS connections.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	SNI *string `json:"sni,omitempty"`

	// InsecureSkipVerify skips TLS certificate verification.
	// +kubebuilder:default=false
	// +optional
	InsecureSkipVerify *bool `json:"insecureSkipVerify,omitempty"`
}

// BackendTLSMode defines the TLS mode for backend connections
// +kubebuilder:validation:Enum=Simple;Mutual;Insecure
type BackendTLSMode string

const (
	// BackendTLSModeSimple uses one-way TLS
	BackendTLSModeSimple BackendTLSMode = "Simple"
	// BackendTLSModeMutual uses mutual TLS
	BackendTLSModeMutual BackendTLSMode = "Mutual"
	// BackendTLSModeInsecure disables TLS
	BackendTLSModeInsecure BackendTLSMode = "Insecure"
)

// ============================================================================
// Backend Status
// ============================================================================

// BackendStatus defines the observed state of Backend
type BackendStatus struct {
	Status `json:",inline"`

	// Endpoints is the list of endpoint statuses.
	// +kubebuilder:validation:MaxItems=100
	// +optional
	Endpoints []EndpointStatus `json:"endpoints,omitempty"`

	// HealthyEndpoints is the number of healthy endpoints.
	HealthyEndpoints int32 `json:"healthyEndpoints,omitempty"`

	// TotalEndpoints is the total number of endpoints.
	TotalEndpoints int32 `json:"totalEndpoints,omitempty"`
}

// EndpointStatus defines the status of an endpoint
type EndpointStatus struct {
	// Address is the address of the endpoint.
	// +kubebuilder:validation:Required
	Address string `json:"address"`

	// Port is the port of the endpoint.
	// +kubebuilder:validation:Required
	Port int32 `json:"port"`

	// Healthy indicates whether the endpoint is healthy.
	Healthy bool `json:"healthy"`

	// LastCheckTime is the last time the endpoint was checked.
	// +optional
	LastCheckTime *metav1.Time `json:"lastCheckTime,omitempty"`

	// LastHealthyTime is the last time the endpoint was healthy.
	// +optional
	LastHealthyTime *metav1.Time `json:"lastHealthyTime,omitempty"`

	// FailureReason is the reason for the endpoint being unhealthy.
	// +optional
	FailureReason *string `json:"failureReason,omitempty"`
}

func init() {
	SchemeBuilder.Register(&Backend{}, &BackendList{})
}
