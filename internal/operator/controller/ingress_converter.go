// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// ConvertedConfig holds the converted configuration from an Ingress resource.
// Routes and Backends are stored as JSON bytes keyed by deterministic identifiers.
type ConvertedConfig struct {
	// Routes maps route keys to their JSON-serialized config.Route.
	Routes map[string][]byte

	// Backends maps backend keys to their JSON-serialized config.Backend.
	Backends map[string][]byte

	// GRPCRoutes maps gRPC route keys to their JSON-serialized config.GRPCRoute.
	GRPCRoutes map[string][]byte

	// GRPCBackends maps gRPC backend keys to their JSON-serialized config.GRPCBackend.
	GRPCBackends map[string][]byte
}

// IngressConverter translates networking.k8s.io/v1 Ingress resources
// into internal config.Route and config.Backend types.
// The converter is stateless and thread-safe.
type IngressConverter struct {
	logger    logr.Logger
	hasLogger bool
}

// IngressConverterOption is a functional option for configuring IngressConverter.
type IngressConverterOption func(*IngressConverter)

// WithLogger sets a custom logger for the IngressConverter.
// When not set, the converter falls back to the global log.Log logger.
func WithLogger(logger logr.Logger) IngressConverterOption {
	return func(c *IngressConverter) {
		c.logger = logger
		c.hasLogger = true
	}
}

// NewIngressConverter creates a new IngressConverter.
func NewIngressConverter(opts ...IngressConverterOption) *IngressConverter {
	c := &IngressConverter{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// getLogger returns the configured logger or falls back to the global log.Log.
func (c *IngressConverter) getLogger() logr.Logger {
	if c.hasLogger {
		return c.logger
	}
	return log.Log
}

// ConvertIngress converts a Kubernetes Ingress resource into gateway configuration.
// It produces config.Route and config.Backend entries for each rule/path combination,
// plus an optional default backend.
//
//nolint:gocognit,gocyclo,nestif // Complexity justified: handles HTTP and gRPC protocols
func (c *IngressConverter) ConvertIngress(
	ingress *networkingv1.Ingress,
) (*ConvertedConfig, error) {
	if ingress == nil {
		return nil, fmt.Errorf("ingress is nil")
	}

	logger := c.getLogger().WithValues(
		"ingress", ingress.Name,
		"namespace", ingress.Namespace,
	)

	result := &ConvertedConfig{
		Routes:       make(map[string][]byte),
		Backends:     make(map[string][]byte),
		GRPCRoutes:   make(map[string][]byte),
		GRPCBackends: make(map[string][]byte),
	}

	annotations := ingress.Annotations
	if annotations == nil {
		annotations = make(map[string]string)
	}

	// Build a set of TLS hosts for quick lookup
	tlsHosts := buildTLSHostSet(ingress)

	// Check if this is a gRPC Ingress
	isGRPC := c.isGRPCIngress(annotations)

	// Process each rule
	for ruleIdx, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}

		for pathIdx, path := range rule.HTTP.Paths {
			if isGRPC {
				// Build gRPC route and backend
				routeKey := ingressGRPCRouteKey(ingress, ruleIdx, pathIdx)
				backendKey := ingressGRPCBackendKey(ingress, path.Backend)

				grpcRoute, err := c.buildGRPCRoute(routeKey, rule.Host, path, annotations, tlsHosts)
				if err != nil {
					logger.Error(err, "failed to build gRPC route",
						"rule", ruleIdx, "path", pathIdx,
					)
					return nil, fmt.Errorf(
						"failed to build gRPC route for rule[%d] path[%d]: %w",
						ruleIdx, pathIdx, err,
					)
				}

				routeJSON, err := json.Marshal(grpcRoute)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal gRPC route %s: %w", routeKey, err)
				}
				result.GRPCRoutes[routeKey] = routeJSON

				grpcBackend := c.buildGRPCBackend(backendKey, path.Backend, annotations)
				backendJSON, err := json.Marshal(grpcBackend)
				if err != nil {
					return nil, fmt.Errorf(
						"failed to marshal gRPC backend %s: %w", backendKey, err,
					)
				}
				result.GRPCBackends[backendKey] = backendJSON
			} else {
				// Build HTTP route and backend
				routeKey := ingressRouteKey(ingress, ruleIdx, pathIdx)
				backendKey := ingressBackendKey(ingress, path.Backend)

				route, err := c.buildRoute(routeKey, rule.Host, path, annotations, tlsHosts)
				if err != nil {
					logger.Error(err, "failed to build route",
						"rule", ruleIdx, "path", pathIdx,
					)
					return nil, fmt.Errorf(
						"failed to build route for rule[%d] path[%d]: %w",
						ruleIdx, pathIdx, err,
					)
				}

				routeJSON, err := json.Marshal(route)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal route %s: %w", routeKey, err)
				}
				result.Routes[routeKey] = routeJSON

				backend := c.buildBackend(backendKey, path.Backend, annotations)
				backendJSON, err := json.Marshal(backend)
				if err != nil {
					return nil, fmt.Errorf(
						"failed to marshal backend %s: %w", backendKey, err,
					)
				}
				result.Backends[backendKey] = backendJSON
			}
		}
	}

	// Process default backend
	if ingress.Spec.DefaultBackend != nil {
		if isGRPC {
			routeKey := ingressGRPCDefaultRouteKey(ingress)
			backendKey := ingressGRPCDefaultBackendKey(ingress)

			grpcRoute, err := c.buildGRPCDefaultRoute(routeKey, *ingress.Spec.DefaultBackend, annotations)
			if err != nil {
				return nil, fmt.Errorf("failed to build default gRPC route: %w", err)
			}
			routeJSON, err := json.Marshal(grpcRoute)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal default gRPC route: %w", err)
			}
			result.GRPCRoutes[routeKey] = routeJSON

			grpcBackend := c.buildGRPCBackend(
				backendKey, *ingress.Spec.DefaultBackend, annotations,
			)
			backendJSON, err := json.Marshal(grpcBackend)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal default gRPC backend: %w", err)
			}
			result.GRPCBackends[backendKey] = backendJSON
		} else {
			routeKey := ingressDefaultRouteKey(ingress)
			backendKey := ingressDefaultBackendKey(ingress)

			route, err := c.buildDefaultRoute(routeKey, *ingress.Spec.DefaultBackend, annotations)
			if err != nil {
				return nil, fmt.Errorf("failed to build default route: %w", err)
			}
			routeJSON, err := json.Marshal(route)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal default route: %w", err)
			}
			result.Routes[routeKey] = routeJSON

			backend := c.buildBackend(
				backendKey, *ingress.Spec.DefaultBackend, annotations,
			)
			backendJSON, err := json.Marshal(backend)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal default backend: %w", err)
			}
			result.Backends[backendKey] = backendJSON
		}
	}

	logger.Info("converted ingress",
		"routes", len(result.Routes),
		"backends", len(result.Backends),
		"grpcRoutes", len(result.GRPCRoutes),
		"grpcBackends", len(result.GRPCBackends),
		"protocol", c.getProtocol(annotations),
	)

	return result, nil
}

// buildRoute creates a config.Route from an Ingress path rule.
func (c *IngressConverter) buildRoute(
	name, host string,
	path networkingv1.HTTPIngressPath,
	annotations map[string]string,
	tlsHosts map[string]bool,
) (*config.Route, error) {
	route := &config.Route{
		Name: name,
	}

	// Build match conditions
	match := config.RouteMatch{}
	uriMatch := buildURIMatch(path)
	if uriMatch != nil {
		match.URI = uriMatch
	}

	route.Match = []config.RouteMatch{match}

	// Build route destination from backend
	dest, err := buildDestination(path.Backend)
	if err != nil {
		return nil, err
	}
	route.Route = []config.RouteDestination{
		{Destination: *dest, Weight: 100},
	}

	// Apply annotations
	c.applyRouteAnnotations(route, annotations)

	// Apply TLS if host is in TLS set
	if host != "" && tlsHosts[host] {
		route.TLS = &config.RouteTLSConfig{
			SNIHosts: []string{host},
		}
		c.applyTLSAnnotations(route, annotations)
	}

	return route, nil
}

// buildDefaultRoute creates a catch-all route for the default backend.
func (c *IngressConverter) buildDefaultRoute(
	name string,
	backend networkingv1.IngressBackend,
	annotations map[string]string,
) (*config.Route, error) {
	route := &config.Route{
		Name: name,
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{Prefix: "/"},
			},
		},
	}

	// Build route destination from default backend
	dest, err := buildDestination(backend)
	if err != nil {
		return nil, err
	}
	route.Route = []config.RouteDestination{
		{Destination: *dest, Weight: 100},
	}

	c.applyRouteAnnotations(route, annotations)
	return route, nil
}

// buildBackend creates a config.Backend from an Ingress backend reference.
func (c *IngressConverter) buildBackend(
	name string,
	backend networkingv1.IngressBackend,
	annotations map[string]string,
) *config.Backend {
	b := &config.Backend{
		Name: name,
	}

	if backend.Service != nil {
		host := config.BackendHost{
			Address: backend.Service.Name,
			Port:    resolveServicePort(backend.Service.Port),
			Weight:  1,
		}
		b.Hosts = []config.BackendHost{host}
	}

	c.applyBackendAnnotations(b, annotations)
	return b
}

// applyRouteAnnotations applies avapigw annotations to a route.
func (c *IngressConverter) applyRouteAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	// Timeout
	if v, ok := annotations[AnnotationTimeout]; ok {
		route.Timeout = parseDuration(v)
	}

	// Retries
	c.applyRetryAnnotations(route, annotations)

	// Rate limit
	c.applyRateLimitAnnotations(route, annotations)

	// CORS
	c.applyCORSAnnotations(route, annotations)

	// Rewrite
	c.applyRewriteAnnotations(route, annotations)

	// Redirect
	c.applyRedirectAnnotations(route, annotations)

	// Security
	c.applySecurityAnnotations(route, annotations)

	// Encoding
	c.applyEncodingAnnotations(route, annotations)

	// Cache
	c.applyCacheAnnotations(route, annotations)

	// Max sessions
	c.applyMaxSessionsAnnotations(route, annotations)

	// Max body size
	c.applyMaxBodySizeAnnotation(route, annotations)
}

// applyRetryAnnotations applies retry-related annotations to a route.
func (c *IngressConverter) applyRetryAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	route.Retries = parseRetryPolicy(annotations)
}

// applyRateLimitAnnotations applies rate limit annotations to a route.
func (c *IngressConverter) applyRateLimitAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	route.RateLimit = parseRateLimitConfig(annotations)
}

// applyCORSAnnotations applies CORS annotations to a route.
func (c *IngressConverter) applyCORSAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	route.CORS = parseCORSConfig(annotations)
}

// applyRewriteAnnotations applies rewrite annotations to a route.
func (c *IngressConverter) applyRewriteAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	uri, hasURI := annotations[AnnotationRewriteURI]
	authority, hasAuthority := annotations[AnnotationRewriteAuthority]

	if !hasURI && !hasAuthority {
		return
	}

	rewrite := &config.RewriteConfig{}
	if hasURI {
		rewrite.URI = uri
	}
	if hasAuthority {
		rewrite.Authority = authority
	}
	route.Rewrite = rewrite
}

// applyRedirectAnnotations applies redirect annotations to a route.
func (c *IngressConverter) applyRedirectAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	uri, hasURI := annotations[AnnotationRedirectURI]
	if !hasURI {
		return
	}

	redirect := &config.RedirectConfig{URI: uri}
	if v, ok := annotations[AnnotationRedirectCode]; ok {
		if code, err := strconv.Atoi(v); err == nil {
			redirect.Code = code
		}
	}
	if v, ok := annotations[AnnotationRedirectScheme]; ok {
		redirect.Scheme = v
	}
	route.Redirect = redirect
}

// applySecurityAnnotations applies security annotations to a route.
func (c *IngressConverter) applySecurityAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	route.Security = parseSecurityConfig(annotations)
}

// applyEncodingAnnotations applies encoding annotations to a route.
func (c *IngressConverter) applyEncodingAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	route.Encoding = parseEncodingConfig(annotations)
}

// applyCacheAnnotations applies cache annotations to a route.
func (c *IngressConverter) applyCacheAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	route.Cache = parseCacheConfig(annotations)
}

// applyMaxSessionsAnnotations applies max sessions annotations to a route.
func (c *IngressConverter) applyMaxSessionsAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	enabledStr, hasEnabled := annotations[AnnotationMaxSessionsEnabled]
	if !hasEnabled {
		return
	}

	ms := &config.MaxSessionsConfig{
		Enabled: enabledStr == annotationValueTrue,
	}
	if v, ok := annotations[AnnotationMaxSessionsMaxConcurrent]; ok {
		if mc, err := strconv.Atoi(v); err == nil {
			ms.MaxConcurrent = mc
		}
	}
	if v, ok := annotations[AnnotationMaxSessionsQueueSize]; ok {
		if qs, err := strconv.Atoi(v); err == nil {
			ms.QueueSize = qs
		}
	}
	if v, ok := annotations[AnnotationMaxSessionsQueueTimeout]; ok {
		ms.QueueTimeout = parseDuration(v)
	}
	route.MaxSessions = ms
}

// applyMaxBodySizeAnnotation applies the max body size annotation to a route.
func (c *IngressConverter) applyMaxBodySizeAnnotation(
	route *config.Route,
	annotations map[string]string,
) {
	v, ok := annotations[AnnotationMaxBodySize]
	if !ok {
		return
	}
	if size, err := strconv.ParseInt(v, 10, 64); err == nil {
		route.RequestLimits = &config.RequestLimitsConfig{
			MaxBodySize: size,
		}
	}
}

// applyTLSAnnotations applies TLS-related annotations to a route.
func (c *IngressConverter) applyTLSAnnotations(
	route *config.Route,
	annotations map[string]string,
) {
	if route.TLS == nil {
		return
	}
	if v, ok := annotations[AnnotationTLSMinVersion]; ok {
		route.TLS.MinVersion = v
	}
	if v, ok := annotations[AnnotationTLSMaxVersion]; ok {
		route.TLS.MaxVersion = v
	}
}

// applyBackendAnnotations applies avapigw annotations to a backend.
func (c *IngressConverter) applyBackendAnnotations(
	backend *config.Backend,
	annotations map[string]string,
) {
	// Health check
	c.applyHealthCheckAnnotations(backend, annotations)

	// Load balancer
	if v, ok := annotations[AnnotationLoadBalancerAlgorithm]; ok {
		backend.LoadBalancer = &config.LoadBalancer{Algorithm: v}
	}

	// Circuit breaker
	c.applyCircuitBreakerAnnotations(backend, annotations)
}

// applyHealthCheckAnnotations applies health check annotations to a backend.
func (c *IngressConverter) applyHealthCheckAnnotations(
	backend *config.Backend,
	annotations map[string]string,
) {
	path, hasPath := annotations[AnnotationHealthCheckPath]
	if !hasPath {
		return
	}

	hc := &config.HealthCheck{Path: path}
	if v, ok := annotations[AnnotationHealthCheckInterval]; ok {
		hc.Interval = parseDuration(v)
	}
	if v, ok := annotations[AnnotationHealthCheckTimeout]; ok {
		hc.Timeout = parseDuration(v)
	}
	if v, ok := annotations[AnnotationHealthCheckHealthyThreshold]; ok {
		if t, err := strconv.Atoi(v); err == nil {
			hc.HealthyThreshold = t
		}
	}
	if v, ok := annotations[AnnotationHealthCheckUnhealthyThreshold]; ok {
		if t, err := strconv.Atoi(v); err == nil {
			hc.UnhealthyThreshold = t
		}
	}
	backend.HealthCheck = hc
}

// applyCircuitBreakerAnnotations applies circuit breaker annotations.
func (c *IngressConverter) applyCircuitBreakerAnnotations(
	backend *config.Backend,
	annotations map[string]string,
) {
	backend.CircuitBreaker = parseCircuitBreakerConfig(annotations)
}

// buildURIMatch creates a URIMatch from an Ingress path.
func buildURIMatch(path networkingv1.HTTPIngressPath) *config.URIMatch {
	pathValue := path.Path
	if pathValue == "" {
		pathValue = "/"
	}

	pathType := networkingv1.PathTypePrefix
	if path.PathType != nil {
		pathType = *path.PathType
	}

	switch pathType {
	case networkingv1.PathTypeExact:
		return &config.URIMatch{Exact: pathValue}
	case networkingv1.PathTypeImplementationSpecific:
		// Treat ImplementationSpecific as prefix match
		return &config.URIMatch{Prefix: pathValue}
	default:
		// PathTypePrefix is the default
		return &config.URIMatch{Prefix: pathValue}
	}
}

// buildDestination creates a Destination from an Ingress backend.
func buildDestination(
	backend networkingv1.IngressBackend,
) (*config.Destination, error) {
	if backend.Service == nil {
		return nil, fmt.Errorf("ingress backend has no service reference")
	}

	return &config.Destination{
		Host: backend.Service.Name,
		Port: resolveServicePort(backend.Service.Port),
	}, nil
}

// resolveServicePort resolves the port from an IngressServiceBackend port spec.
func resolveServicePort(port networkingv1.ServiceBackendPort) int {
	if port.Number > 0 {
		return int(port.Number)
	}
	// If only name is specified, use a default port.
	// The actual resolution would happen at the gateway level.
	return DefaultHTTPPort
}

// buildTLSHostSet creates a set of hosts that have TLS configured.
func buildTLSHostSet(ingress *networkingv1.Ingress) map[string]bool {
	hosts := make(map[string]bool)
	for _, tls := range ingress.Spec.TLS {
		for _, host := range tls.Hosts {
			hosts[host] = true
		}
	}
	return hosts
}

// ingressRouteKey generates a deterministic key for an Ingress-derived route.
func ingressRouteKey(
	ingress *networkingv1.Ingress, ruleIdx, pathIdx int,
) string {
	return fmt.Sprintf("ingress-%s-%s-r%d-p%d",
		ingress.Namespace, ingress.Name, ruleIdx, pathIdx)
}

// ingressBackendKey generates a deterministic key for an Ingress backend.
func ingressBackendKey(
	ingress *networkingv1.Ingress,
	backend networkingv1.IngressBackend,
) string {
	if backend.Service != nil {
		port := resolveServicePort(backend.Service.Port)
		return fmt.Sprintf("ingress-%s-%s-%s-%d",
			ingress.Namespace, ingress.Name,
			backend.Service.Name, port)
	}
	return fmt.Sprintf("ingress-%s-%s-unknown",
		ingress.Namespace, ingress.Name)
}

// ingressDefaultRouteKey generates a key for the default backend route.
func ingressDefaultRouteKey(ingress *networkingv1.Ingress) string {
	return fmt.Sprintf("ingress-%s-%s-default",
		ingress.Namespace, ingress.Name)
}

// ingressDefaultBackendKey generates a key for the default backend.
func ingressDefaultBackendKey(ingress *networkingv1.Ingress) string {
	return fmt.Sprintf("ingress-%s-%s-default-backend",
		ingress.Namespace, ingress.Name)
}

// splitCSV splits a comma-separated string into trimmed parts.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// parseDuration parses a duration string (e.g., "30s", "5m") into config.Duration.
// Returns 0 if the string cannot be parsed.
func parseDuration(s string) config.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return config.Duration(d)
}

// isGRPCIngress checks if the Ingress is configured for gRPC protocol.
func (c *IngressConverter) isGRPCIngress(annotations map[string]string) bool {
	protocol, ok := annotations[AnnotationProtocol]
	if !ok {
		return false
	}
	return strings.EqualFold(protocol, ProtocolGRPC)
}

// getProtocol returns the protocol from annotations, defaulting to HTTP.
func (c *IngressConverter) getProtocol(annotations map[string]string) string {
	protocol, ok := annotations[AnnotationProtocol]
	if !ok {
		return ProtocolHTTP
	}
	return strings.ToLower(protocol)
}

// buildGRPCRoute creates a config.GRPCRoute from an Ingress path rule.
func (c *IngressConverter) buildGRPCRoute(
	name, host string,
	path networkingv1.HTTPIngressPath,
	annotations map[string]string,
	tlsHosts map[string]bool,
) (*config.GRPCRoute, error) {
	route := &config.GRPCRoute{
		Name: name,
	}

	// Build match conditions
	match := c.buildGRPCRouteMatch(host, path, annotations)
	route.Match = []config.GRPCRouteMatch{match}

	// Build route destination from backend
	dest, err := buildDestination(path.Backend)
	if err != nil {
		return nil, err
	}
	route.Route = []config.RouteDestination{
		{Destination: *dest, Weight: 100},
	}

	// Apply annotations
	c.applyGRPCRouteAnnotations(route, annotations)

	// Apply TLS if host is in TLS set
	if host != "" && tlsHosts[host] {
		route.TLS = &config.RouteTLSConfig{
			SNIHosts: []string{host},
		}
		c.applyGRPCTLSAnnotations(route, annotations)
	}

	return route, nil
}

// buildGRPCRouteMatch creates a GRPCRouteMatch from Ingress path and annotations.
func (c *IngressConverter) buildGRPCRouteMatch(
	host string,
	path networkingv1.HTTPIngressPath,
	annotations map[string]string,
) config.GRPCRouteMatch {
	match := config.GRPCRouteMatch{}

	// Set authority match from host
	if host != "" {
		match.Authority = &config.StringMatch{Exact: host}
	}

	// Set service match from annotation or path
	if service, ok := annotations[AnnotationGRPCService]; ok && service != "" {
		matchType := annotations[AnnotationGRPCServiceMatchType]
		match.Service = buildStringMatch(service, matchType)
	} else if path.Path != "" && path.Path != "/" {
		// Use path as service prefix if no explicit service annotation
		// Remove leading slash and use as prefix
		servicePath := strings.TrimPrefix(path.Path, "/")
		if servicePath != "" {
			match.Service = &config.StringMatch{Prefix: servicePath}
		}
	}

	// Set method match from annotation
	if method, ok := annotations[AnnotationGRPCMethod]; ok && method != "" {
		matchType := annotations[AnnotationGRPCMethodMatchType]
		match.Method = buildStringMatch(method, matchType)
	}

	return match
}

// buildStringMatch creates a StringMatch based on value and match type.
func buildStringMatch(value, matchType string) *config.StringMatch {
	if value == "" {
		return nil
	}

	switch strings.ToLower(matchType) {
	case MatchTypeExact:
		return &config.StringMatch{Exact: value}
	case MatchTypeRegex:
		return &config.StringMatch{Regex: value}
	case MatchTypePrefix:
		return &config.StringMatch{Prefix: value}
	default:
		return &config.StringMatch{Prefix: value}
	}
}

// buildGRPCDefaultRoute creates a catch-all gRPC route for the default backend.
func (c *IngressConverter) buildGRPCDefaultRoute(
	name string,
	backend networkingv1.IngressBackend,
	annotations map[string]string,
) (*config.GRPCRoute, error) {
	route := &config.GRPCRoute{
		Name: name,
		Match: []config.GRPCRouteMatch{
			{
				// Match all services with wildcard
				Service: &config.StringMatch{Prefix: ""},
			},
		},
	}

	// Build route destination from default backend
	dest, err := buildDestination(backend)
	if err != nil {
		return nil, err
	}
	route.Route = []config.RouteDestination{
		{Destination: *dest, Weight: 100},
	}

	c.applyGRPCRouteAnnotations(route, annotations)
	return route, nil
}

// buildGRPCBackend creates a config.GRPCBackend from an Ingress backend reference.
func (c *IngressConverter) buildGRPCBackend(
	name string,
	backend networkingv1.IngressBackend,
	annotations map[string]string,
) *config.GRPCBackend {
	b := &config.GRPCBackend{
		Name: name,
	}

	if backend.Service != nil {
		host := config.BackendHost{
			Address: backend.Service.Name,
			Port:    resolveServicePort(backend.Service.Port),
			Weight:  1,
		}
		b.Hosts = []config.BackendHost{host}
	}

	c.applyGRPCBackendAnnotations(b, annotations)
	return b
}

// applyGRPCRouteAnnotations applies avapigw annotations to a gRPC route.
func (c *IngressConverter) applyGRPCRouteAnnotations(
	route *config.GRPCRoute,
	annotations map[string]string,
) {
	// Timeout
	if v, ok := annotations[AnnotationTimeout]; ok {
		route.Timeout = parseDuration(v)
	}

	// Retries (gRPC-specific)
	c.applyGRPCRetryAnnotations(route, annotations)

	// Rate limit
	c.applyGRPCRateLimitAnnotations(route, annotations)

	// CORS
	c.applyGRPCCORSAnnotations(route, annotations)

	// Security
	c.applyGRPCSecurityAnnotations(route, annotations)

	// Encoding
	c.applyGRPCEncodingAnnotations(route, annotations)

	// Cache
	c.applyGRPCCacheAnnotations(route, annotations)
}

// applyGRPCRetryAnnotations applies gRPC retry annotations to a route.
func (c *IngressConverter) applyGRPCRetryAnnotations(
	route *config.GRPCRoute,
	annotations map[string]string,
) {
	attemptsStr, hasAttempts := annotations[AnnotationRetryAttempts]
	perTryTimeout, hasPerTry := annotations[AnnotationRetryPerTryTimeout]
	retryOn, hasRetryOn := annotations[AnnotationGRPCRetryOn]
	backoffBase, hasBackoffBase := annotations[AnnotationGRPCBackoffBaseInterval]
	backoffMax, hasBackoffMax := annotations[AnnotationGRPCBackoffMaxInterval]

	// Fall back to standard retry-on if gRPC-specific not set
	if !hasRetryOn {
		retryOn, hasRetryOn = annotations[AnnotationRetryOn]
	}

	if !hasAttempts && !hasPerTry && !hasRetryOn && !hasBackoffBase && !hasBackoffMax {
		return
	}

	retry := &config.GRPCRetryPolicy{}
	if hasAttempts {
		if v, err := strconv.Atoi(attemptsStr); err == nil {
			retry.Attempts = v
		}
	}
	if hasPerTry {
		retry.PerTryTimeout = parseDuration(perTryTimeout)
	}
	if hasRetryOn {
		retry.RetryOn = retryOn
	}
	if hasBackoffBase {
		retry.BackoffBaseInterval = parseDuration(backoffBase)
	}
	if hasBackoffMax {
		retry.BackoffMaxInterval = parseDuration(backoffMax)
	}
	route.Retries = retry
}

// applyGRPCRateLimitAnnotations applies rate limit annotations to a gRPC route.
func (c *IngressConverter) applyGRPCRateLimitAnnotations(
	route *config.GRPCRoute,
	annotations map[string]string,
) {
	route.RateLimit = parseRateLimitConfig(annotations)
}

// applyGRPCCORSAnnotations applies CORS annotations to a gRPC route.
func (c *IngressConverter) applyGRPCCORSAnnotations(
	route *config.GRPCRoute,
	annotations map[string]string,
) {
	route.CORS = parseCORSConfig(annotations)
}

// applyGRPCSecurityAnnotations applies security annotations to a gRPC route.
func (c *IngressConverter) applyGRPCSecurityAnnotations(
	route *config.GRPCRoute,
	annotations map[string]string,
) {
	route.Security = parseSecurityConfig(annotations)
}

// applyGRPCEncodingAnnotations applies encoding annotations to a gRPC route.
func (c *IngressConverter) applyGRPCEncodingAnnotations(
	route *config.GRPCRoute,
	annotations map[string]string,
) {
	route.Encoding = parseEncodingConfig(annotations)
}

// applyGRPCCacheAnnotations applies cache annotations to a gRPC route.
func (c *IngressConverter) applyGRPCCacheAnnotations(
	route *config.GRPCRoute,
	annotations map[string]string,
) {
	route.Cache = parseCacheConfig(annotations)
}

// applyGRPCTLSAnnotations applies TLS-related annotations to a gRPC route.
func (c *IngressConverter) applyGRPCTLSAnnotations(
	route *config.GRPCRoute,
	annotations map[string]string,
) {
	if route.TLS == nil {
		return
	}
	if v, ok := annotations[AnnotationTLSMinVersion]; ok {
		route.TLS.MinVersion = v
	}
	if v, ok := annotations[AnnotationTLSMaxVersion]; ok {
		route.TLS.MaxVersion = v
	}
}

// applyGRPCBackendAnnotations applies avapigw annotations to a gRPC backend.
func (c *IngressConverter) applyGRPCBackendAnnotations(
	backend *config.GRPCBackend,
	annotations map[string]string,
) {
	// gRPC Health check
	c.applyGRPCHealthCheckAnnotations(backend, annotations)

	// Load balancer
	if v, ok := annotations[AnnotationLoadBalancerAlgorithm]; ok {
		backend.LoadBalancer = &config.LoadBalancer{Algorithm: v}
	}

	// Circuit breaker
	c.applyGRPCCircuitBreakerAnnotations(backend, annotations)

	// Connection pool
	c.applyGRPCConnectionPoolAnnotations(backend, annotations)
}

// applyGRPCHealthCheckAnnotations applies gRPC health check annotations to a backend.
func (c *IngressConverter) applyGRPCHealthCheckAnnotations(
	backend *config.GRPCBackend,
	annotations map[string]string,
) {
	enabledStr, hasEnabled := annotations[AnnotationGRPCHealthCheckEnabled]
	if !hasEnabled {
		return
	}

	hc := &config.GRPCHealthCheckConfig{
		Enabled: enabledStr == annotationValueTrue,
	}

	if v, ok := annotations[AnnotationGRPCHealthCheckService]; ok {
		hc.Service = v
	}
	if v, ok := annotations[AnnotationGRPCHealthCheckInterval]; ok {
		hc.Interval = parseDuration(v)
	}
	if v, ok := annotations[AnnotationGRPCHealthCheckTimeout]; ok {
		hc.Timeout = parseDuration(v)
	}
	if v, ok := annotations[AnnotationGRPCHealthCheckHealthyThreshold]; ok {
		if t, err := strconv.Atoi(v); err == nil {
			hc.HealthyThreshold = t
		}
	}
	if v, ok := annotations[AnnotationGRPCHealthCheckUnhealthyThreshold]; ok {
		if t, err := strconv.Atoi(v); err == nil {
			hc.UnhealthyThreshold = t
		}
	}
	backend.HealthCheck = hc
}

// applyGRPCCircuitBreakerAnnotations applies circuit breaker annotations to a gRPC backend.
func (c *IngressConverter) applyGRPCCircuitBreakerAnnotations(
	backend *config.GRPCBackend,
	annotations map[string]string,
) {
	backend.CircuitBreaker = parseCircuitBreakerConfig(annotations)
}

// applyGRPCConnectionPoolAnnotations applies connection pool annotations to a gRPC backend.
func (c *IngressConverter) applyGRPCConnectionPoolAnnotations(
	backend *config.GRPCBackend,
	annotations map[string]string,
) {
	maxIdle, hasMaxIdle := annotations[AnnotationGRPCMaxIdleConns]
	maxConns, hasMaxConns := annotations[AnnotationGRPCMaxConnsPerHost]
	idleTimeout, hasIdleTimeout := annotations[AnnotationGRPCIdleConnTimeout]

	if !hasMaxIdle && !hasMaxConns && !hasIdleTimeout {
		return
	}

	pool := &config.GRPCConnectionPoolConfig{}
	if hasMaxIdle {
		if v, err := strconv.Atoi(maxIdle); err == nil {
			pool.MaxIdleConns = v
		}
	}
	if hasMaxConns {
		if v, err := strconv.Atoi(maxConns); err == nil {
			pool.MaxConnsPerHost = v
		}
	}
	if hasIdleTimeout {
		pool.IdleConnTimeout = parseDuration(idleTimeout)
	}
	backend.ConnectionPool = pool
}

// ingressGRPCRouteKey generates a deterministic key for an Ingress-derived gRPC route.
func ingressGRPCRouteKey(
	ingress *networkingv1.Ingress, ruleIdx, pathIdx int,
) string {
	return fmt.Sprintf("ingress-grpc-%s-%s-r%d-p%d",
		ingress.Namespace, ingress.Name, ruleIdx, pathIdx)
}

// ingressGRPCBackendKey generates a deterministic key for an Ingress gRPC backend.
func ingressGRPCBackendKey(
	ingress *networkingv1.Ingress,
	backend networkingv1.IngressBackend,
) string {
	if backend.Service != nil {
		port := resolveServicePort(backend.Service.Port)
		return fmt.Sprintf("ingress-grpc-%s-%s-%s-%d",
			ingress.Namespace, ingress.Name,
			backend.Service.Name, port)
	}
	return fmt.Sprintf("ingress-grpc-%s-%s-unknown",
		ingress.Namespace, ingress.Name)
}

// ingressGRPCDefaultRouteKey generates a key for the default gRPC backend route.
func ingressGRPCDefaultRouteKey(ingress *networkingv1.Ingress) string {
	return fmt.Sprintf("ingress-grpc-%s-%s-default",
		ingress.Namespace, ingress.Name)
}

// ingressGRPCDefaultBackendKey generates a key for the default gRPC backend.
func ingressGRPCDefaultBackendKey(ingress *networkingv1.Ingress) string {
	return fmt.Sprintf("ingress-grpc-%s-%s-default-backend",
		ingress.Namespace, ingress.Name)
}
