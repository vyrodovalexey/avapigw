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

// ValidationWarning represents a configuration validation warning.
type ValidationWarning struct {
	Path    string
	Message string
}

// ValidationWarnings is a collection of validation warnings.
type ValidationWarnings []ValidationWarning

// Validator validates gateway configuration.
type Validator struct {
	errors   ValidationErrors
	warnings ValidationWarnings
}

// NewValidator creates a new configuration validator.
func NewValidator() *Validator {
	return &Validator{
		errors:   make(ValidationErrors, 0),
		warnings: make(ValidationWarnings, 0),
	}
}

// Warnings returns any validation warnings collected during validation.
func (v *Validator) Warnings() ValidationWarnings {
	return v.warnings
}

// addWarning adds a validation warning.
func (v *Validator) addWarning(path, message string) {
	v.warnings = append(v.warnings, ValidationWarning{Path: path, Message: message})
}

// ValidateConfig validates a gateway configuration.
func ValidateConfig(config *GatewayConfig) error {
	v := NewValidator()
	return v.Validate(config)
}

// ValidateConfigWithWarnings validates a gateway configuration and returns warnings.
func ValidateConfigWithWarnings(config *GatewayConfig) (ValidationWarnings, error) {
	v := NewValidator()
	err := v.Validate(config)
	return v.Warnings(), err
}

// Validate validates the configuration and returns any errors.
func (v *Validator) Validate(config *GatewayConfig) error {
	v.errors = make(ValidationErrors, 0)
	v.warnings = make(ValidationWarnings, 0)

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
	v.validateGRPCRoutes(spec.GRPCRoutes)
	v.validateGRPCBackends(spec.GRPCBackends)

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

	if spec.MaxSessions != nil {
		v.validateMaxSessions(spec.MaxSessions, "spec.maxSessions")
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
		v.validateListenerTimeouts(listener.Timeouts, path+".timeouts")
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
		ProtocolHTTP:  true,
		ProtocolHTTPS: true,
		ProtocolHTTP2: true,
		ProtocolGRPC:  true,
	}
	switch {
	case listener.Protocol == "":
		v.addError(path+".protocol", "protocol is required")
	case !validProtocols[listener.Protocol]:
		v.addError(path+".protocol", "protocol must be HTTP, HTTPS, HTTP2, or GRPC")
	}

	// Validate gRPC-specific configuration
	if listener.Protocol == ProtocolGRPC {
		v.validateGRPCListenerConfig(listener.GRPC, path+".grpc")
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

// validateListenerTimeouts validates listener timeout configuration.
func (v *Validator) validateListenerTimeouts(timeouts *ListenerTimeouts, path string) {
	if timeouts == nil {
		return
	}

	if timeouts.ReadTimeout.Duration() < 0 {
		v.addError(path+".readTimeout", "readTimeout cannot be negative")
	}

	if timeouts.ReadHeaderTimeout.Duration() < 0 {
		v.addError(path+".readHeaderTimeout", "readHeaderTimeout cannot be negative")
	}

	if timeouts.WriteTimeout.Duration() < 0 {
		v.addError(path+".writeTimeout", "writeTimeout cannot be negative")
	}

	if timeouts.IdleTimeout.Duration() < 0 {
		v.addError(path+".idleTimeout", "idleTimeout cannot be negative")
	}

	// Validate that readHeaderTimeout <= readTimeout if both are set
	if timeouts.ReadHeaderTimeout.Duration() > 0 && timeouts.ReadTimeout.Duration() > 0 {
		if timeouts.ReadHeaderTimeout.Duration() > timeouts.ReadTimeout.Duration() {
			v.addError(path+".readHeaderTimeout", "readHeaderTimeout should not exceed readTimeout")
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

	if route.MaxSessions != nil {
		v.validateMaxSessions(route.MaxSessions, path+".maxSessions")
	}

	if route.TLS != nil {
		v.validateRouteTLSConfig(route.TLS, path+".tls")
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

	if backend.TLS != nil {
		v.validateBackendTLSConfig(backend.TLS, path+".tls")
	}

	if backend.MaxSessions != nil {
		v.validateMaxSessions(backend.MaxSessions, path+".maxSessions")
	}

	if backend.RateLimit != nil {
		v.validateRateLimit(backend.RateLimit, path+".rateLimit")
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

// validateMaxSessions validates max sessions configuration.
func (v *Validator) validateMaxSessions(ms *MaxSessionsConfig, path string) {
	if !ms.Enabled {
		return
	}

	if ms.MaxConcurrent <= 0 {
		v.addError(path+".maxConcurrent", "maxConcurrent must be positive when enabled")
	}

	if ms.QueueSize < 0 {
		v.addError(path+".queueSize", "queueSize cannot be negative")
	}

	if ms.QueueSize > 0 && ms.QueueTimeout.Duration() <= 0 {
		v.addError(path+".queueTimeout", "queueTimeout must be positive when queueSize > 0")
	}

	if ms.QueueTimeout.Duration() < 0 {
		v.addError(path+".queueTimeout", "queueTimeout cannot be negative")
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

// validateGRPCListenerConfig validates gRPC listener configuration.
func (v *Validator) validateGRPCListenerConfig(cfg *GRPCListenerConfig, path string) {
	if cfg == nil {
		return
	}

	if cfg.MaxRecvMsgSize < 0 {
		v.addError(path+".maxRecvMsgSize", "maxRecvMsgSize cannot be negative")
	}

	if cfg.MaxSendMsgSize < 0 {
		v.addError(path+".maxSendMsgSize", "maxSendMsgSize cannot be negative")
	}

	if cfg.Keepalive != nil {
		v.validateGRPCKeepaliveConfig(cfg.Keepalive, path+".keepalive")
	}

	if cfg.TLS != nil {
		v.validateTLSConfig(cfg.TLS, path+".tls")
	}
}

// validateGRPCKeepaliveConfig validates gRPC keepalive configuration.
func (v *Validator) validateGRPCKeepaliveConfig(cfg *GRPCKeepaliveConfig, path string) {
	if cfg.Time.Duration() < 0 {
		v.addError(path+".time", "time cannot be negative")
	}

	if cfg.Timeout.Duration() < 0 {
		v.addError(path+".timeout", "timeout cannot be negative")
	}

	if cfg.MaxConnectionIdle.Duration() < 0 {
		v.addError(path+".maxConnectionIdle", "maxConnectionIdle cannot be negative")
	}

	if cfg.MaxConnectionAge.Duration() < 0 {
		v.addError(path+".maxConnectionAge", "maxConnectionAge cannot be negative")
	}

	if cfg.MaxConnectionAgeGrace.Duration() < 0 {
		v.addError(path+".maxConnectionAgeGrace", "maxConnectionAgeGrace cannot be negative")
	}
}

// validateTLSConfig validates TLS configuration.
func (v *Validator) validateTLSConfig(cfg *TLSConfig, path string) {
	if cfg.Enabled {
		// When Vault is enabled, certificates are obtained from Vault PKI
		// and certFile/keyFile are not required.
		vaultEnabled := cfg.Vault != nil && cfg.Vault.Enabled
		if cfg.CertFile == "" && !vaultEnabled {
			v.addError(path+".certFile", "certFile is required when TLS is enabled")
		}
		if cfg.KeyFile == "" && !vaultEnabled {
			v.addError(path+".keyFile", "keyFile is required when TLS is enabled")
		}
	}
}

// validateGRPCRoutes validates gRPC route configurations.
func (v *Validator) validateGRPCRoutes(routes []GRPCRoute) {
	names := make(map[string]bool)

	for i, route := range routes {
		path := fmt.Sprintf("spec.grpcRoutes[%d]", i)
		v.validateSingleGRPCRoute(&route, path, names)
	}
}

// validateSingleGRPCRoute validates a single gRPC route configuration.
func (v *Validator) validateSingleGRPCRoute(route *GRPCRoute, path string, names map[string]bool) {
	// Validate route name
	switch {
	case route.Name == "":
		v.addError(path+".name", "route name is required")
	case names[route.Name]:
		v.addError(path+".name", fmt.Sprintf("duplicate gRPC route name: %s", route.Name))
	default:
		names[route.Name] = true
	}

	// Validate match conditions
	if len(route.Match) == 0 {
		v.addError(path+".match", "at least one match condition is required")
	}

	for j, match := range route.Match {
		matchPath := fmt.Sprintf("%s.match[%d]", path, j)
		v.validateGRPCRouteMatch(&match, matchPath)
	}

	// Validate destinations
	if len(route.Route) == 0 {
		v.addError(path+".route", "at least one destination is required")
	}

	totalWeight := 0
	for j, dest := range route.Route {
		destPath := fmt.Sprintf("%s.route[%d]", path, j)
		totalWeight += v.validateRouteDestination(&dest, destPath)
	}

	if len(route.Route) > 1 && totalWeight > 0 && totalWeight != 100 {
		v.addError(path+".route", fmt.Sprintf("route weights must sum to 100, got %d", totalWeight))
	}

	// Validate timeout
	if route.Timeout.Duration() < 0 {
		v.addError(path+".timeout", "timeout cannot be negative")
	}

	// Validate retry policy
	if route.Retries != nil {
		v.validateGRPCRetryPolicy(route.Retries, path+".retries")
	}

	// Validate rate limit
	if route.RateLimit != nil {
		v.validateRateLimit(route.RateLimit, path+".rateLimit")
	}

	// Validate route-level TLS
	if route.TLS != nil {
		v.validateRouteTLSConfig(route.TLS, path+".tls")
	}
}

// validateGRPCRouteMatch validates a gRPC route match configuration.
func (v *Validator) validateGRPCRouteMatch(match *GRPCRouteMatch, path string) {
	// At least one match condition should be specified
	if match.IsEmpty() {
		v.addError(path, "at least one match condition (service, method, metadata, or authority) is required")
	}

	// Validate service match
	if match.Service != nil {
		v.validateStringMatch(match.Service, path+".service")
	}

	// Validate method match
	if match.Method != nil {
		v.validateStringMatch(match.Method, path+".method")
	}

	// Validate authority match
	if match.Authority != nil {
		v.validateStringMatch(match.Authority, path+".authority")
	}

	// Validate metadata matches
	for i, meta := range match.Metadata {
		metaPath := fmt.Sprintf("%s.metadata[%d]", path, i)
		v.validateMetadataMatch(&meta, metaPath)
	}
}

// validateStringMatch validates a string match configuration.
func (v *Validator) validateStringMatch(match *StringMatch, path string) {
	if match == nil {
		return
	}

	count := 0
	if match.Exact != "" {
		count++
	}
	if match.Prefix != "" {
		count++
	}
	if match.Regex != "" {
		count++
		if err := util.ValidateRegex(match.Regex); err != nil {
			v.addError(path+".regex", err.Error())
		}
	}

	if count > 1 {
		v.addError(path, "only one of exact, prefix, or regex can be specified")
	}
}

// validateMetadataMatch validates a metadata match configuration.
func (v *Validator) validateMetadataMatch(match *MetadataMatch, path string) {
	if match.Name == "" {
		v.addError(path+".name", "metadata name is required")
	}

	// Validate regex if specified
	if match.Regex != "" {
		if err := util.ValidateRegex(match.Regex); err != nil {
			v.addError(path+".regex", err.Error())
		}
	}

	// Check for conflicting conditions
	if match.Present != nil && match.Absent != nil {
		v.addError(path, "present and absent cannot both be specified")
	}
}

// validateGRPCRetryPolicy validates gRPC retry policy configuration.
func (v *Validator) validateGRPCRetryPolicy(retry *GRPCRetryPolicy, path string) {
	if retry.Attempts < 0 {
		v.addError(path+".attempts", "attempts cannot be negative")
	}

	if retry.PerTryTimeout.Duration() < 0 {
		v.addError(path+".perTryTimeout", "perTryTimeout cannot be negative")
	}

	if retry.BackoffBaseInterval.Duration() < 0 {
		v.addError(path+".backoffBaseInterval", "backoffBaseInterval cannot be negative")
	}

	if retry.BackoffMaxInterval.Duration() < 0 {
		v.addError(path+".backoffMaxInterval", "backoffMaxInterval cannot be negative")
	}

	// Validate retry status codes
	if retry.RetryOn != "" {
		v.validateGRPCRetryStatusCodes(retry.RetryOn, path+".retryOn")
	}
}

// validateGRPCRetryStatusCodes validates gRPC retry status codes.
func (v *Validator) validateGRPCRetryStatusCodes(retryOn, path string) {
	validCodes := map[string]bool{
		"canceled":           true,
		"deadline-exceeded":  true,
		"internal":           true,
		"resource-exhausted": true,
		"unavailable":        true,
		"unknown":            true,
		"aborted":            true,
		"data-loss":          true,
	}

	codes := strings.Split(retryOn, ",")
	for _, code := range codes {
		code = strings.TrimSpace(strings.ToLower(code))
		if code != "" && !validCodes[code] {
			v.addError(path, fmt.Sprintf("invalid gRPC retry status code: %s", code))
		}
	}
}

// validateGRPCBackends validates gRPC backend configurations.
func (v *Validator) validateGRPCBackends(backends []GRPCBackend) {
	names := make(map[string]bool)

	for i, backend := range backends {
		path := fmt.Sprintf("spec.grpcBackends[%d]", i)
		v.validateSingleGRPCBackend(&backend, path, names)
	}
}

// validateSingleGRPCBackend validates a single gRPC backend configuration.
func (v *Validator) validateSingleGRPCBackend(backend *GRPCBackend, path string, names map[string]bool) {
	// Validate backend name
	switch {
	case backend.Name == "":
		v.addError(path+".name", "backend name is required")
	case names[backend.Name]:
		v.addError(path+".name", fmt.Sprintf("duplicate gRPC backend name: %s", backend.Name))
	default:
		names[backend.Name] = true
	}

	// Validate hosts
	if len(backend.Hosts) == 0 {
		v.addError(path+".hosts", "at least one host is required")
	}

	for j, host := range backend.Hosts {
		hostPath := fmt.Sprintf("%s.hosts[%d]", path, j)
		v.validateBackendHost(&host, hostPath)
	}

	// Validate health check
	if backend.HealthCheck != nil {
		v.validateGRPCHealthCheckConfig(backend.HealthCheck, path+".healthCheck")
	}

	// Validate load balancer
	if backend.LoadBalancer != nil {
		v.validateLoadBalancer(backend.LoadBalancer, path+".loadBalancer")
	}

	// Validate TLS
	if backend.TLS != nil {
		v.validateTLSConfig(backend.TLS, path+".tls")
	}

	// Validate connection pool
	if backend.ConnectionPool != nil {
		v.validateGRPCConnectionPoolConfig(backend.ConnectionPool, path+".connectionPool")
	}
}

// validateGRPCHealthCheckConfig validates gRPC health check configuration.
func (v *Validator) validateGRPCHealthCheckConfig(cfg *GRPCHealthCheckConfig, path string) {
	if cfg.Interval.Duration() < 0 {
		v.addError(path+".interval", "interval cannot be negative")
	}

	if cfg.Timeout.Duration() < 0 {
		v.addError(path+".timeout", "timeout cannot be negative")
	}

	if cfg.HealthyThreshold < 0 {
		v.addError(path+".healthyThreshold", "healthyThreshold cannot be negative")
	}

	if cfg.UnhealthyThreshold < 0 {
		v.addError(path+".unhealthyThreshold", "unhealthyThreshold cannot be negative")
	}
}

// validateGRPCConnectionPoolConfig validates gRPC connection pool configuration.
func (v *Validator) validateGRPCConnectionPoolConfig(cfg *GRPCConnectionPoolConfig, path string) {
	if cfg.MaxIdleConns < 0 {
		v.addError(path+".maxIdleConns", "maxIdleConns cannot be negative")
	}

	if cfg.MaxConnsPerHost < 0 {
		v.addError(path+".maxConnsPerHost", "maxConnsPerHost cannot be negative")
	}

	if cfg.IdleConnTimeout.Duration() < 0 {
		v.addError(path+".idleConnTimeout", "idleConnTimeout cannot be negative")
	}
}

// validateBackendTLSConfig validates backend TLS configuration.
func (v *Validator) validateBackendTLSConfig(cfg *BackendTLSConfig, path string) {
	if cfg == nil {
		return
	}

	v.validateBackendTLSMode(cfg, path)
	v.validateBackendTLSMutual(cfg, path)
	v.validateBackendTLSVersions(cfg, path)

	// Validate Vault configuration
	if cfg.Vault != nil && cfg.Vault.Enabled {
		v.validateVaultBackendTLSConfig(cfg.Vault, path+".vault")
	}
}

// validateBackendTLSMode validates the TLS mode.
func (v *Validator) validateBackendTLSMode(cfg *BackendTLSConfig, path string) {
	if cfg.Mode == "" {
		return
	}
	validModes := map[string]bool{
		TLSModeSimple:   true,
		TLSModeMutual:   true,
		TLSModeInsecure: true,
	}
	if !validModes[cfg.Mode] {
		v.addError(path+".mode",
			fmt.Sprintf("invalid TLS mode: %s (must be SIMPLE, MUTUAL, or INSECURE)", cfg.Mode))
	}
}

// validateBackendTLSMutual validates mTLS configuration.
func (v *Validator) validateBackendTLSMutual(cfg *BackendTLSConfig, path string) {
	if cfg.Mode != TLSModeMutual {
		return
	}
	vaultEnabled := cfg.Vault != nil && cfg.Vault.Enabled
	if cfg.CertFile == "" && !vaultEnabled {
		v.addError(path+".certFile", "certFile is required for MUTUAL TLS mode (or enable Vault)")
	}
	if cfg.KeyFile == "" && !vaultEnabled {
		v.addError(path+".keyFile", "keyFile is required for MUTUAL TLS mode (or enable Vault)")
	}
}

// validateBackendTLSVersions validates TLS version configuration.
func (v *Validator) validateBackendTLSVersions(cfg *BackendTLSConfig, path string) {
	validVersions := map[string]bool{
		"TLS10": true, "TLS11": true, "TLS12": true, "TLS13": true,
	}
	deprecatedVersions := map[string]bool{
		"TLS10": true, "TLS11": true,
	}
	if cfg.MinVersion != "" {
		if !validVersions[cfg.MinVersion] {
			v.addError(path+".minVersion", fmt.Sprintf("invalid TLS version: %s", cfg.MinVersion))
		} else if deprecatedVersions[cfg.MinVersion] {
			v.addWarning(path+".minVersion",
				fmt.Sprintf("TLS version %s is deprecated (RFC 8996), use TLS12 or TLS13", cfg.MinVersion))
		}
	}
	if cfg.MaxVersion != "" {
		if !validVersions[cfg.MaxVersion] {
			v.addError(path+".maxVersion", fmt.Sprintf("invalid TLS version: %s", cfg.MaxVersion))
		} else if deprecatedVersions[cfg.MaxVersion] {
			v.addWarning(path+".maxVersion",
				fmt.Sprintf("TLS version %s is deprecated (RFC 8996), use TLS12 or TLS13", cfg.MaxVersion))
		}
	}
}

// validateVaultBackendTLSConfig validates Vault backend TLS configuration.
func (v *Validator) validateVaultBackendTLSConfig(cfg *VaultBackendTLSConfig, path string) {
	if cfg == nil || !cfg.Enabled {
		return
	}

	if cfg.PKIMount == "" {
		v.addError(path+".pkiMount", "pkiMount is required when Vault is enabled")
	}

	if cfg.Role == "" {
		v.addError(path+".role", "role is required when Vault is enabled")
	}

	if cfg.CommonName == "" {
		v.addError(path+".commonName", "commonName is required when Vault is enabled")
	}
}

// validateRouteTLSConfig validates route-level TLS configuration.
func (v *Validator) validateRouteTLSConfig(cfg *RouteTLSConfig, path string) {
	if cfg == nil {
		return
	}

	// Validate certificate files
	v.validateRouteTLSCertificates(cfg, path)

	// Validate SNI hosts
	v.validateRouteTLSSNIHosts(cfg, path)

	// Validate TLS versions
	v.validateRouteTLSVersions(cfg, path)

	// Validate Vault configuration
	v.validateRouteTLSVault(cfg, path)

	// Validate client validation configuration
	v.validateRouteClientValidation(cfg.ClientValidation, path+".clientValidation")
}

// validateRouteTLSCertificates validates route TLS certificate configuration.
func (v *Validator) validateRouteTLSCertificates(cfg *RouteTLSConfig, path string) {
	hasFiles := cfg.CertFile != "" || cfg.KeyFile != ""
	hasVault := cfg.Vault != nil && cfg.Vault.Enabled

	// If files are partially specified, both must be present
	if hasFiles && !hasVault {
		if cfg.CertFile == "" {
			v.addError(path+".certFile", "certFile is required when keyFile is specified")
		}
		if cfg.KeyFile == "" {
			v.addError(path+".keyFile", "keyFile is required when certFile is specified")
		}
	}

	// Warn if neither files nor Vault is configured but SNI hosts are specified
	if !hasFiles && !hasVault && len(cfg.SNIHosts) > 0 {
		v.addError(path, "certificate source (certFile/keyFile or vault) is required when sniHosts are specified")
	}
}

// validateRouteTLSSNIHosts validates route TLS SNI hosts configuration.
func (v *Validator) validateRouteTLSSNIHosts(cfg *RouteTLSConfig, path string) {
	for i, host := range cfg.SNIHosts {
		if err := util.ValidateHostname(host); err != nil {
			v.addError(fmt.Sprintf("%s.sniHosts[%d]", path, i), err.Error())
		}
	}
}

// validateRouteTLSVersions validates route TLS version configuration.
func (v *Validator) validateRouteTLSVersions(cfg *RouteTLSConfig, path string) {
	validVersions := map[string]bool{
		"":      true,
		"TLS10": true,
		"TLS11": true,
		"TLS12": true,
		"TLS13": true,
	}

	if !validVersions[cfg.MinVersion] {
		v.addError(path+".minVersion", fmt.Sprintf("invalid TLS version: %s", cfg.MinVersion))
	}

	if !validVersions[cfg.MaxVersion] {
		v.addError(path+".maxVersion", fmt.Sprintf("invalid TLS version: %s", cfg.MaxVersion))
	}

	// Validate min <= max if both are specified
	if cfg.MinVersion != "" && cfg.MaxVersion != "" {
		versionOrder := map[string]int{"TLS10": 1, "TLS11": 2, "TLS12": 3, "TLS13": 4}
		minOrder, minOk := versionOrder[cfg.MinVersion]
		maxOrder, maxOk := versionOrder[cfg.MaxVersion]
		if minOk && maxOk && minOrder > maxOrder {
			v.addError(path+".minVersion",
				fmt.Sprintf("minVersion (%s) cannot be greater than maxVersion (%s)", cfg.MinVersion, cfg.MaxVersion))
		}
	}
}

// validateRouteTLSVault validates route TLS Vault configuration.
func (v *Validator) validateRouteTLSVault(cfg *RouteTLSConfig, path string) {
	if cfg.Vault == nil || !cfg.Vault.Enabled {
		return
	}

	if cfg.Vault.PKIMount == "" {
		v.addError(path+".vault.pkiMount", "pkiMount is required when Vault is enabled")
	}

	if cfg.Vault.Role == "" {
		v.addError(path+".vault.role", "role is required when Vault is enabled")
	}

	if cfg.Vault.CommonName == "" {
		v.addError(path+".vault.commonName", "commonName is required when Vault is enabled")
	}
}

// validateRouteClientValidation validates route client certificate validation configuration.
func (v *Validator) validateRouteClientValidation(cfg *RouteClientValidationConfig, path string) {
	if cfg == nil || !cfg.Enabled {
		return
	}

	// CA file is required for client validation
	if cfg.CAFile == "" {
		v.addError(path+".caFile", "caFile is required when client validation is enabled")
	}
}
