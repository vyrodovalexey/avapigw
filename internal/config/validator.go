package config

import (
	"fmt"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/util"
)

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Path    string
	Message string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s", e.Path, e.Message)
	}
	return e.Message
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

// Error implements the error interface.
func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	if len(e) == 1 {
		return e[0].Error()
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d validation errors:\n", len(e)))
	for i, err := range e {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, err.Error()))
	}
	return sb.String()
}

// HasErrors returns true if there are validation errors.
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// Validator validates gateway configuration.
type Validator struct {
	errors ValidationErrors
}

// NewValidator creates a new configuration validator.
func NewValidator() *Validator {
	return &Validator{
		errors: make(ValidationErrors, 0),
	}
}

// ValidateConfig validates a gateway configuration.
func ValidateConfig(config *GatewayConfig) error {
	v := NewValidator()
	return v.Validate(config)
}

// Validate validates the configuration and returns any errors.
func (v *Validator) Validate(config *GatewayConfig) error {
	v.errors = make(ValidationErrors, 0)

	if config == nil {
		v.addError("", "configuration is nil")
		return v.errors
	}

	v.validateRoot(config)
	v.validateMetadata(&config.Metadata)
	v.validateSpec(&config.Spec)

	if v.errors.HasErrors() {
		return v.errors
	}
	return nil
}

// validateRoot validates root-level fields.
func (v *Validator) validateRoot(config *GatewayConfig) {
	if config.APIVersion == "" {
		v.addError("apiVersion", "apiVersion is required")
	} else if !strings.HasPrefix(config.APIVersion, "gateway.avapigw.io/") {
		v.addError("apiVersion", "apiVersion must start with 'gateway.avapigw.io/'")
	}

	if config.Kind == "" {
		v.addError("kind", "kind is required")
	} else if config.Kind != "Gateway" {
		v.addError("kind", "kind must be 'Gateway'")
	}
}

// validateMetadata validates metadata fields.
func (v *Validator) validateMetadata(metadata *Metadata) {
	if metadata.Name == "" {
		v.addError("metadata.name", "name is required")
	}
}

// validateSpec validates the gateway spec.
func (v *Validator) validateSpec(spec *GatewaySpec) {
	if len(spec.Listeners) == 0 {
		v.addError("spec.listeners", "at least one listener is required")
	}

	v.validateListeners(spec.Listeners)
	v.validateRoutes(spec.Routes, spec.Backends)
	v.validateBackends(spec.Backends)

	if spec.RateLimit != nil {
		v.validateRateLimit(spec.RateLimit, "spec.rateLimit")
	}

	if spec.CircuitBreaker != nil {
		v.validateCircuitBreaker(spec.CircuitBreaker, "spec.circuitBreaker")
	}

	if spec.CORS != nil {
		v.validateCORS(spec.CORS, "spec.cors")
	}

	if spec.Observability != nil {
		v.validateObservability(spec.Observability, "spec.observability")
	}
}

// validateListeners validates listener configurations.
func (v *Validator) validateListeners(listeners []Listener) {
	names := make(map[string]bool)
	ports := make(map[int]string)

	for i, listener := range listeners {
		path := fmt.Sprintf("spec.listeners[%d]", i)
		v.validateListenerName(&listener, path, names)
		v.validateListenerPort(&listener, path, ports)
		v.validateListenerProtocol(&listener, path)
		v.validateListenerBind(&listener, path)
		v.validateListenerHosts(&listener, path)
	}
}

// validateListenerName validates listener name uniqueness.
func (v *Validator) validateListenerName(listener *Listener, path string, names map[string]bool) {
	switch {
	case listener.Name == "":
		v.addError(path+".name", "listener name is required")
	case names[listener.Name]:
		v.addError(path+".name", fmt.Sprintf("duplicate listener name: %s", listener.Name))
	default:
		names[listener.Name] = true
	}
}

// validateListenerPort validates listener port uniqueness.
func (v *Validator) validateListenerPort(listener *Listener, path string, ports map[int]string) {
	if err := util.ValidatePort(listener.Port); err != nil {
		v.addError(path+".port", err.Error())
		return
	}
	if existingName, exists := ports[listener.Port]; exists {
		v.addError(path+".port", fmt.Sprintf("port %d already used by listener %s", listener.Port, existingName))
		return
	}
	ports[listener.Port] = listener.Name
}

// validateListenerProtocol validates listener protocol.
func (v *Validator) validateListenerProtocol(listener *Listener, path string) {
	validProtocols := map[string]bool{
		"HTTP":  true,
		"HTTPS": true,
		"HTTP2": true,
	}
	switch {
	case listener.Protocol == "":
		v.addError(path+".protocol", "protocol is required")
	case !validProtocols[listener.Protocol]:
		v.addError(path+".protocol", "protocol must be HTTP, HTTPS, or HTTP2")
	}
}

// validateListenerBind validates listener bind address.
func (v *Validator) validateListenerBind(listener *Listener, path string) {
	if listener.Bind != "" {
		if err := util.ValidateIPAddress(listener.Bind); err != nil {
			v.addError(path+".bind", err.Error())
		}
	}
}

// validateListenerHosts validates listener hosts.
func (v *Validator) validateListenerHosts(listener *Listener, path string) {
	for j, host := range listener.Hosts {
		if err := util.ValidateHostname(host); err != nil {
			v.addError(fmt.Sprintf("%s.hosts[%d]", path, j), err.Error())
		}
	}
}

// validateRoutes validates route configurations.
func (v *Validator) validateRoutes(routes []Route, backends []Backend) {
	names := make(map[string]bool)
	backendNames := make(map[string]bool)

	for _, backend := range backends {
		backendNames[backend.Name] = true
	}

	for i, route := range routes {
		path := fmt.Sprintf("spec.routes[%d]", i)
		v.validateSingleRoute(&route, path, names)
	}
}

// validateSingleRoute validates a single route configuration.
func (v *Validator) validateSingleRoute(route *Route, path string, names map[string]bool) {
	v.validateRouteName(route, path, names)
	v.validateRouteMatches(route, path)
	v.validateRouteDestinations(route, path)
	v.validateRouteOptions(route, path)
}

// validateRouteName validates route name uniqueness.
func (v *Validator) validateRouteName(route *Route, path string, names map[string]bool) {
	switch {
	case route.Name == "":
		v.addError(path+".name", "route name is required")
	case names[route.Name]:
		v.addError(path+".name", fmt.Sprintf("duplicate route name: %s", route.Name))
	default:
		names[route.Name] = true
	}
}

// validateRouteMatches validates route match conditions.
func (v *Validator) validateRouteMatches(route *Route, path string) {
	for j, match := range route.Match {
		matchPath := fmt.Sprintf("%s.match[%d]", path, j)
		v.validateRouteMatch(&match, matchPath)
	}
}

// validateRouteDestinations validates route destinations and weights.
func (v *Validator) validateRouteDestinations(route *Route, path string) {
	if len(route.Route) == 0 && route.Redirect == nil && route.DirectResponse == nil {
		v.addError(path, "route must have at least one destination, redirect, or directResponse")
	}

	totalWeight := 0
	for j, dest := range route.Route {
		destPath := fmt.Sprintf("%s.route[%d]", path, j)
		totalWeight += v.validateRouteDestination(&dest, destPath)
	}

	if len(route.Route) > 1 && totalWeight > 0 && totalWeight != 100 {
		v.addError(path+".route", fmt.Sprintf("route weights must sum to 100, got %d", totalWeight))
	}
}

// validateRouteDestination validates a single route destination.
func (v *Validator) validateRouteDestination(dest *RouteDestination, destPath string) int {
	if dest.Destination.Host == "" {
		v.addError(destPath+".destination.host", "destination host is required")
	}

	if dest.Destination.Port != 0 {
		if err := util.ValidatePort(dest.Destination.Port); err != nil {
			v.addError(destPath+".destination.port", err.Error())
		}
	}

	if dest.Weight < 0 || dest.Weight > 100 {
		v.addError(destPath+".weight", "weight must be between 0 and 100")
	}
	return dest.Weight
}

// validateRouteOptions validates route timeout, retries, redirect, direct response, and rate limit.
func (v *Validator) validateRouteOptions(route *Route, path string) {
	if route.Timeout.Duration() < 0 {
		v.addError(path+".timeout", "timeout cannot be negative")
	}

	if route.Retries != nil {
		v.validateRetryPolicy(route.Retries, path+".retries")
	}

	if route.Redirect != nil {
		v.validateRedirect(route.Redirect, path+".redirect")
	}

	if route.DirectResponse != nil {
		v.validateDirectResponse(route.DirectResponse, path+".directResponse")
	}

	if route.RateLimit != nil {
		v.validateRateLimit(route.RateLimit, path+".rateLimit")
	}
}

// validateRouteMatch validates a route match configuration.
func (v *Validator) validateRouteMatch(match *RouteMatch, path string) {
	if match.URI != nil {
		v.validateURIMatch(match.URI, path+".uri")
	}

	for i, method := range match.Methods {
		if err := util.ValidateHTTPMethod(method); err != nil {
			v.addError(fmt.Sprintf("%s.methods[%d]", path, i), err.Error())
		}
	}

	for i, header := range match.Headers {
		headerPath := fmt.Sprintf("%s.headers[%d]", path, i)
		v.validateHeaderMatch(&header, headerPath)
	}

	for i, query := range match.QueryParams {
		queryPath := fmt.Sprintf("%s.queryParams[%d]", path, i)
		v.validateQueryParamMatch(&query, queryPath)
	}
}

// validateURIMatch validates a URI match configuration.
func (v *Validator) validateURIMatch(uri *URIMatch, path string) {
	count := 0
	if uri.Exact != "" {
		count++
	}
	if uri.Prefix != "" {
		count++
	}
	if uri.Regex != "" {
		count++
		if err := util.ValidateRegex(uri.Regex); err != nil {
			v.addError(path+".regex", err.Error())
		}
	}

	if count > 1 {
		v.addError(path, "only one of exact, prefix, or regex can be specified")
	}
}

// validateHeaderMatch validates a header match configuration.
func (v *Validator) validateHeaderMatch(header *HeaderMatch, path string) {
	if header.Name == "" {
		v.addError(path+".name", "header name is required")
	} else if err := util.ValidateHeaderName(header.Name); err != nil {
		v.addError(path+".name", err.Error())
	}

	if header.Regex != "" {
		if err := util.ValidateRegex(header.Regex); err != nil {
			v.addError(path+".regex", err.Error())
		}
	}
}

// validateQueryParamMatch validates a query parameter match configuration.
func (v *Validator) validateQueryParamMatch(query *QueryParamMatch, path string) {
	if query.Name == "" {
		v.addError(path+".name", "query parameter name is required")
	}

	if query.Regex != "" {
		if err := util.ValidateRegex(query.Regex); err != nil {
			v.addError(path+".regex", err.Error())
		}
	}
}

// validateBackends validates backend configurations.
func (v *Validator) validateBackends(backends []Backend) {
	names := make(map[string]bool)

	for i, backend := range backends {
		path := fmt.Sprintf("spec.backends[%d]", i)
		v.validateSingleBackend(&backend, path, names)
	}
}

// validateSingleBackend validates a single backend configuration.
func (v *Validator) validateSingleBackend(backend *Backend, path string, names map[string]bool) {
	v.validateBackendName(backend, path, names)
	v.validateBackendHosts(backend, path)

	if backend.HealthCheck != nil {
		v.validateHealthCheck(backend.HealthCheck, path+".healthCheck")
	}

	if backend.LoadBalancer != nil {
		v.validateLoadBalancer(backend.LoadBalancer, path+".loadBalancer")
	}
}

// validateBackendName validates backend name uniqueness.
func (v *Validator) validateBackendName(backend *Backend, path string, names map[string]bool) {
	switch {
	case backend.Name == "":
		v.addError(path+".name", "backend name is required")
	case names[backend.Name]:
		v.addError(path+".name", fmt.Sprintf("duplicate backend name: %s", backend.Name))
	default:
		names[backend.Name] = true
	}
}

// validateBackendHosts validates backend hosts.
func (v *Validator) validateBackendHosts(backend *Backend, path string) {
	if len(backend.Hosts) == 0 {
		v.addError(path+".hosts", "at least one host is required")
	}

	for j, host := range backend.Hosts {
		hostPath := fmt.Sprintf("%s.hosts[%d]", path, j)
		v.validateBackendHost(&host, hostPath)
	}
}

// validateBackendHost validates a single backend host.
func (v *Validator) validateBackendHost(host *BackendHost, hostPath string) {
	if host.Address == "" {
		v.addError(hostPath+".address", "host address is required")
	}

	if err := util.ValidatePort(host.Port); err != nil {
		v.addError(hostPath+".port", err.Error())
	}

	if host.Weight < 0 {
		v.addError(hostPath+".weight", "weight cannot be negative")
	}
}

// validateHealthCheck validates health check configuration.
func (v *Validator) validateHealthCheck(hc *HealthCheck, path string) {
	if hc.Path == "" {
		v.addError(path+".path", "health check path is required")
	}

	if hc.Interval.Duration() < 0 {
		v.addError(path+".interval", "interval cannot be negative")
	}

	if hc.Timeout.Duration() < 0 {
		v.addError(path+".timeout", "timeout cannot be negative")
	}

	if hc.HealthyThreshold < 0 {
		v.addError(path+".healthyThreshold", "healthyThreshold cannot be negative")
	}

	if hc.UnhealthyThreshold < 0 {
		v.addError(path+".unhealthyThreshold", "unhealthyThreshold cannot be negative")
	}
}

// validateLoadBalancer validates load balancer configuration.
func (v *Validator) validateLoadBalancer(lb *LoadBalancer, path string) {
	validAlgorithms := map[string]bool{
		"":                     true,
		LoadBalancerRoundRobin: true,
		LoadBalancerWeighted:   true,
		LoadBalancerLeastConn:  true,
		LoadBalancerRandom:     true,
	}

	if !validAlgorithms[lb.Algorithm] {
		v.addError(path+".algorithm", fmt.Sprintf("invalid algorithm: %s", lb.Algorithm))
	}
}

// validateRetryPolicy validates retry policy configuration.
func (v *Validator) validateRetryPolicy(retry *RetryPolicy, path string) {
	if retry.Attempts < 0 {
		v.addError(path+".attempts", "attempts cannot be negative")
	}

	if retry.PerTryTimeout.Duration() < 0 {
		v.addError(path+".perTryTimeout", "perTryTimeout cannot be negative")
	}
}

// validateRedirect validates redirect configuration.
func (v *Validator) validateRedirect(redirect *RedirectConfig, path string) {
	validCodes := map[int]bool{
		0:   true, // Default
		301: true,
		302: true,
		303: true,
		307: true,
		308: true,
	}

	if !validCodes[redirect.Code] {
		v.addError(path+".code", fmt.Sprintf("invalid redirect code: %d", redirect.Code))
	}

	if redirect.Scheme != "" && redirect.Scheme != "http" && redirect.Scheme != "https" {
		v.addError(path+".scheme", "scheme must be http or https")
	}

	if redirect.Port != 0 {
		if err := util.ValidatePort(redirect.Port); err != nil {
			v.addError(path+".port", err.Error())
		}
	}
}

// validateDirectResponse validates direct response configuration.
func (v *Validator) validateDirectResponse(dr *DirectResponseConfig, path string) {
	if err := util.ValidateHTTPStatusCode(dr.Status); err != nil {
		v.addError(path+".status", err.Error())
	}
}

// validateRateLimit validates rate limit configuration.
func (v *Validator) validateRateLimit(rl *RateLimitConfig, path string) {
	if rl.Enabled {
		if rl.RequestsPerSecond <= 0 {
			v.addError(path+".requestsPerSecond", "requestsPerSecond must be positive when enabled")
		}

		if rl.Burst < 0 {
			v.addError(path+".burst", "burst cannot be negative")
		}
	}
}

// validateCircuitBreaker validates circuit breaker configuration.
func (v *Validator) validateCircuitBreaker(cb *CircuitBreakerConfig, path string) {
	if cb.Enabled {
		if cb.Threshold <= 0 {
			v.addError(path+".threshold", "threshold must be positive when enabled")
		}

		if cb.Timeout.Duration() <= 0 {
			v.addError(path+".timeout", "timeout must be positive when enabled")
		}

		if cb.HalfOpenRequests < 0 {
			v.addError(path+".halfOpenRequests", "halfOpenRequests cannot be negative")
		}
	}
}

// validateCORS validates CORS configuration.
func (v *Validator) validateCORS(cors *CORSConfig, path string) {
	for i, method := range cors.AllowMethods {
		if err := util.ValidateHTTPMethod(method); err != nil {
			v.addError(fmt.Sprintf("%s.allowMethods[%d]", path, i), err.Error())
		}
	}

	if cors.MaxAge < 0 {
		v.addError(path+".maxAge", "maxAge cannot be negative")
	}
}

// validateObservability validates observability configuration.
func (v *Validator) validateObservability(obs *ObservabilityConfig, path string) {
	if obs.Metrics != nil {
		if obs.Metrics.Path != "" && !strings.HasPrefix(obs.Metrics.Path, "/") {
			v.addError(path+".metrics.path", "metrics path must start with /")
		}

		if obs.Metrics.Port != 0 {
			if err := util.ValidatePort(obs.Metrics.Port); err != nil {
				v.addError(path+".metrics.port", err.Error())
			}
		}
	}

	if obs.Tracing != nil {
		if obs.Tracing.SamplingRate < 0 || obs.Tracing.SamplingRate > 1 {
			v.addError(path+".tracing.samplingRate", "samplingRate must be between 0 and 1")
		}
	}

	if obs.Logging != nil {
		validLevels := map[string]bool{
			"":      true,
			"debug": true,
			"info":  true,
			"warn":  true,
			"error": true,
		}

		if !validLevels[strings.ToLower(obs.Logging.Level)] {
			v.addError(path+".logging.level", fmt.Sprintf("invalid log level: %s", obs.Logging.Level))
		}

		validFormats := map[string]bool{
			"":        true,
			"json":    true,
			"console": true,
		}

		if !validFormats[strings.ToLower(obs.Logging.Format)] {
			v.addError(path+".logging.format", fmt.Sprintf("invalid log format: %s", obs.Logging.Format))
		}
	}
}

// addError adds a validation error.
func (v *Validator) addError(path, message string) {
	v.errors = append(v.errors, ValidationError{Path: path, Message: message})
}
