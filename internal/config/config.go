// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"time"
)

// GatewayConfig represents the root configuration for the API Gateway.
type GatewayConfig struct {
	APIVersion string      `yaml:"apiVersion" json:"apiVersion"`
	Kind       string      `yaml:"kind" json:"kind"`
	Metadata   Metadata    `yaml:"metadata" json:"metadata"`
	Spec       GatewaySpec `yaml:"spec" json:"spec"`
}

// Metadata contains metadata about the gateway configuration.
type Metadata struct {
	Name        string            `yaml:"name" json:"name"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

// GatewaySpec contains the main gateway specification.
type GatewaySpec struct {
	Listeners      []Listener            `yaml:"listeners" json:"listeners"`
	Routes         []Route               `yaml:"routes,omitempty" json:"routes,omitempty"`
	Backends       []Backend             `yaml:"backends,omitempty" json:"backends,omitempty"`
	GRPCRoutes     []GRPCRoute           `yaml:"grpcRoutes,omitempty" json:"grpcRoutes,omitempty"`
	GRPCBackends   []GRPCBackend         `yaml:"grpcBackends,omitempty" json:"grpcBackends,omitempty"`
	RateLimit      *RateLimitConfig      `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`
	CORS           *CORSConfig           `yaml:"cors,omitempty" json:"cors,omitempty"`
	Observability  *ObservabilityConfig  `yaml:"observability,omitempty" json:"observability,omitempty"`
}

// Listener represents a network listener configuration.
type Listener struct {
	Name     string              `yaml:"name" json:"name"`
	Port     int                 `yaml:"port" json:"port"`
	Protocol string              `yaml:"protocol" json:"protocol"`
	Hosts    []string            `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Bind     string              `yaml:"bind,omitempty" json:"bind,omitempty"`
	GRPC     *GRPCListenerConfig `yaml:"grpc,omitempty" json:"grpc,omitempty"`
}

// Route represents a routing rule configuration.
type Route struct {
	Name           string                `yaml:"name" json:"name"`
	Match          []RouteMatch          `yaml:"match,omitempty" json:"match,omitempty"`
	Route          []RouteDestination    `yaml:"route,omitempty" json:"route,omitempty"`
	Timeout        Duration              `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retries        *RetryPolicy          `yaml:"retries,omitempty" json:"retries,omitempty"`
	Redirect       *RedirectConfig       `yaml:"redirect,omitempty" json:"redirect,omitempty"`
	Rewrite        *RewriteConfig        `yaml:"rewrite,omitempty" json:"rewrite,omitempty"`
	DirectResponse *DirectResponseConfig `yaml:"directResponse,omitempty" json:"directResponse,omitempty"`
	Headers        *HeaderManipulation   `yaml:"headers,omitempty" json:"headers,omitempty"`
	Mirror         *MirrorConfig         `yaml:"mirror,omitempty" json:"mirror,omitempty"`
	Fault          *FaultInjection       `yaml:"fault,omitempty" json:"fault,omitempty"`
	RateLimit      *RateLimitConfig      `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	Transform      *TransformConfig      `yaml:"transform,omitempty" json:"transform,omitempty"`
	Cache          *CacheConfig          `yaml:"cache,omitempty" json:"cache,omitempty"`
	Encoding       *EncodingConfig       `yaml:"encoding,omitempty" json:"encoding,omitempty"`
}

// RouteMatch represents matching conditions for a route.
type RouteMatch struct {
	URI         *URIMatch         `yaml:"uri,omitempty" json:"uri,omitempty"`
	Methods     []string          `yaml:"methods,omitempty" json:"methods,omitempty"`
	Headers     []HeaderMatch     `yaml:"headers,omitempty" json:"headers,omitempty"`
	QueryParams []QueryParamMatch `yaml:"queryParams,omitempty" json:"queryParams,omitempty"`
}

// URIMatch represents URI matching configuration.
type URIMatch struct {
	Exact  string `yaml:"exact,omitempty" json:"exact,omitempty"`
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Regex  string `yaml:"regex,omitempty" json:"regex,omitempty"`
}

// MatchType returns the type of URI match configured.
func (u *URIMatch) MatchType() string {
	if u.Exact != "" {
		return "exact"
	}
	if u.Prefix != "" {
		return "prefix"
	}
	if u.Regex != "" {
		return "regex"
	}
	return ""
}

// IsEmpty returns true if no match is configured.
func (u *URIMatch) IsEmpty() bool {
	return u.Exact == "" && u.Prefix == "" && u.Regex == ""
}

// HeaderMatch represents header matching configuration.
type HeaderMatch struct {
	Name    string `yaml:"name" json:"name"`
	Exact   string `yaml:"exact,omitempty" json:"exact,omitempty"`
	Prefix  string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Regex   string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Present *bool  `yaml:"present,omitempty" json:"present,omitempty"`
	Absent  *bool  `yaml:"absent,omitempty" json:"absent,omitempty"`
}

// QueryParamMatch represents query parameter matching configuration.
type QueryParamMatch struct {
	Name    string `yaml:"name" json:"name"`
	Exact   string `yaml:"exact,omitempty" json:"exact,omitempty"`
	Regex   string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Present *bool  `yaml:"present,omitempty" json:"present,omitempty"`
}

// RouteDestination represents a destination for routing.
type RouteDestination struct {
	Destination Destination `yaml:"destination" json:"destination"`
	Weight      int         `yaml:"weight,omitempty" json:"weight,omitempty"`
}

// Destination represents a backend destination.
type Destination struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

// Backend represents a backend service configuration.
type Backend struct {
	Name         string        `yaml:"name" json:"name"`
	Hosts        []BackendHost `yaml:"hosts" json:"hosts"`
	HealthCheck  *HealthCheck  `yaml:"healthCheck,omitempty" json:"healthCheck,omitempty"`
	LoadBalancer *LoadBalancer `yaml:"loadBalancer,omitempty" json:"loadBalancer,omitempty"`
}

// BackendHost represents a single backend host.
type BackendHost struct {
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
	Weight  int    `yaml:"weight,omitempty" json:"weight,omitempty"`
}

// HealthCheck represents health check configuration.
type HealthCheck struct {
	Path               string   `yaml:"path" json:"path"`
	Interval           Duration `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout            Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	HealthyThreshold   int      `yaml:"healthyThreshold,omitempty" json:"healthyThreshold,omitempty"`
	UnhealthyThreshold int      `yaml:"unhealthyThreshold,omitempty" json:"unhealthyThreshold,omitempty"`
}

// LoadBalancer represents load balancer configuration.
type LoadBalancer struct {
	Algorithm string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
}

// LoadBalancerAlgorithm constants.
const (
	LoadBalancerRoundRobin = "roundRobin"
	LoadBalancerWeighted   = "weighted"
	LoadBalancerLeastConn  = "leastConn"
	LoadBalancerRandom     = "random"
)

// RetryPolicy represents retry configuration.
type RetryPolicy struct {
	Attempts      int      `yaml:"attempts" json:"attempts"`
	PerTryTimeout Duration `yaml:"perTryTimeout,omitempty" json:"perTryTimeout,omitempty"`
	RetryOn       string   `yaml:"retryOn,omitempty" json:"retryOn,omitempty"`
}

// RateLimitConfig represents rate limiting configuration.
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled" json:"enabled"`
	RequestsPerSecond int  `yaml:"requestsPerSecond" json:"requestsPerSecond"`
	Burst             int  `yaml:"burst" json:"burst"`
	PerClient         bool `yaml:"perClient,omitempty" json:"perClient,omitempty"`
}

// CircuitBreakerConfig represents circuit breaker configuration.
type CircuitBreakerConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	Threshold        int      `yaml:"threshold" json:"threshold"`
	Timeout          Duration `yaml:"timeout" json:"timeout"`
	HalfOpenRequests int      `yaml:"halfOpenRequests,omitempty" json:"halfOpenRequests,omitempty"`
}

// CORSConfig represents CORS configuration.
type CORSConfig struct {
	AllowOrigins     []string `yaml:"allowOrigins,omitempty" json:"allowOrigins,omitempty"`
	AllowMethods     []string `yaml:"allowMethods,omitempty" json:"allowMethods,omitempty"`
	AllowHeaders     []string `yaml:"allowHeaders,omitempty" json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `yaml:"exposeHeaders,omitempty" json:"exposeHeaders,omitempty"`
	MaxAge           int      `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`
	AllowCredentials bool     `yaml:"allowCredentials,omitempty" json:"allowCredentials,omitempty"`
}

// ObservabilityConfig represents observability configuration.
type ObservabilityConfig struct {
	Metrics *MetricsConfig `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	Tracing *TracingConfig `yaml:"tracing,omitempty" json:"tracing,omitempty"`
	Logging *LoggingConfig `yaml:"logging,omitempty" json:"logging,omitempty"`
}

// MetricsConfig represents metrics configuration.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path,omitempty" json:"path,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
}

// TracingConfig represents tracing configuration.
type TracingConfig struct {
	Enabled      bool    `yaml:"enabled" json:"enabled"`
	SamplingRate float64 `yaml:"samplingRate,omitempty" json:"samplingRate,omitempty"`
	OTLPEndpoint string  `yaml:"otlpEndpoint,omitempty" json:"otlpEndpoint,omitempty"`
	ServiceName  string  `yaml:"serviceName,omitempty" json:"serviceName,omitempty"`
}

// LoggingConfig represents logging configuration.
type LoggingConfig struct {
	Level  string `yaml:"level,omitempty" json:"level,omitempty"`
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	Output string `yaml:"output,omitempty" json:"output,omitempty"`
}

// RedirectConfig represents HTTP redirect configuration.
type RedirectConfig struct {
	URI        string `yaml:"uri,omitempty" json:"uri,omitempty"`
	Code       int    `yaml:"code,omitempty" json:"code,omitempty"`
	Scheme     string `yaml:"scheme,omitempty" json:"scheme,omitempty"`
	Host       string `yaml:"host,omitempty" json:"host,omitempty"`
	Port       int    `yaml:"port,omitempty" json:"port,omitempty"`
	StripQuery bool   `yaml:"stripQuery,omitempty" json:"stripQuery,omitempty"`
}

// RewriteConfig represents URL rewrite configuration.
type RewriteConfig struct {
	URI       string `yaml:"uri,omitempty" json:"uri,omitempty"`
	Authority string `yaml:"authority,omitempty" json:"authority,omitempty"`
}

// DirectResponseConfig represents direct response configuration.
type DirectResponseConfig struct {
	Status  int               `yaml:"status" json:"status"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// HeaderManipulation represents header manipulation configuration.
type HeaderManipulation struct {
	Request  *HeaderOperation `yaml:"request,omitempty" json:"request,omitempty"`
	Response *HeaderOperation `yaml:"response,omitempty" json:"response,omitempty"`
}

// HeaderOperation represents header operations.
type HeaderOperation struct {
	Set    map[string]string `yaml:"set,omitempty" json:"set,omitempty"`
	Add    map[string]string `yaml:"add,omitempty" json:"add,omitempty"`
	Remove []string          `yaml:"remove,omitempty" json:"remove,omitempty"`
}

// FaultInjection represents fault injection configuration.
type FaultInjection struct {
	Delay *FaultDelay `yaml:"delay,omitempty" json:"delay,omitempty"`
	Abort *FaultAbort `yaml:"abort,omitempty" json:"abort,omitempty"`
}

// FaultDelay represents delay fault injection.
type FaultDelay struct {
	FixedDelay Duration `yaml:"fixedDelay" json:"fixedDelay"`
	Percentage float64  `yaml:"percentage,omitempty" json:"percentage,omitempty"`
}

// FaultAbort represents abort fault injection.
type FaultAbort struct {
	HTTPStatus int     `yaml:"httpStatus" json:"httpStatus"`
	Percentage float64 `yaml:"percentage,omitempty" json:"percentage,omitempty"`
}

// MirrorConfig represents traffic mirroring configuration.
type MirrorConfig struct {
	Destination Destination `yaml:"destination" json:"destination"`
	Percentage  float64     `yaml:"percentage,omitempty" json:"percentage,omitempty"`
}

// Duration is a wrapper around time.Duration that supports YAML/JSON marshaling.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	// Remove quotes if present
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// Duration returns the time.Duration value.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *GatewayConfig {
	return &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: Metadata{
			Name: "default-gateway",
		},
		Spec: GatewaySpec{
			Listeners: []Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: "HTTP",
					Hosts:    []string{"*"},
					Bind:     "0.0.0.0",
				},
			},
			Observability: &ObservabilityConfig{
				Metrics: &MetricsConfig{
					Enabled: true,
					Path:    "/metrics",
				},
				Logging: &LoggingConfig{
					Level:  "info",
					Format: "json",
				},
			},
		},
	}
}

// IsEmpty returns true if the RouteMatch has no conditions.
func (rm *RouteMatch) IsEmpty() bool {
	if rm.URI != nil && !rm.URI.IsEmpty() {
		return false
	}
	if len(rm.Methods) > 0 {
		return false
	}
	if len(rm.Headers) > 0 {
		return false
	}
	if len(rm.QueryParams) > 0 {
		return false
	}
	return true
}
